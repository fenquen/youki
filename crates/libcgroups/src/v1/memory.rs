use std::collections::HashMap;
use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Write;
use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use oci_spec::runtime::LinuxMemory;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrapIoResult, WrappedIoError};
use crate::stats::{
    self, parse_single_value, MemoryData, MemoryStats, ParseFlatKeyedDataError, StatsProvider,
};

const CGROUP_MEMORY_SWAP_LIMIT: &str = "memory.memsw.limit_in_bytes";
const CGROUP_MEMORY_LIMIT: &str = "memory.limit_in_bytes";
const CGROUP_MEMORY_USAGE: &str = "memory.usage_in_bytes";
const CGROUP_MEMORY_MAX_USAGE: &str = "memory.max_usage_in_bytes";
const CGROUP_MEMORY_SWAPPINESS: &str = "memory.swappiness";
const CGROUP_MEMORY_RESERVATION: &str = "memory.soft_limit_in_bytes";
const CGROUP_MEMORY_OOM_CONTROL: &str = "memory.oom_control";

const CGROUP_KERNEL_MEMORY_LIMIT: &str = "memory.kmem.limit_in_bytes";
const CGROUP_KERNEL_TCP_MEMORY_LIMIT: &str = "memory.kmem.tcp.limit_in_bytes";

// Shows various memory statistics
const MEMORY_STAT: &str = "memory.stat";
//
const MEMORY_USE_HIERARCHY: &str = "memory.use_hierarchy";
// Prefix for memory cgroup files
const MEMORY_PREFIX: &str = "memory";
// Prefix for memory and swap cgroup files
const MEMORY_AND_SWAP_PREFIX: &str = "memory.memsw";
// Prefix for kernel memory cgroup files
const MEMORY_KERNEL_PREFIX: &str = "memory.kmem";
// Prefix for kernel tcp memory cgroup files
const MEMORY_KERNEL_TCP_PREFIX: &str = "memory.kmem.tcp";
// Memory usage in bytes
const MEMORY_USAGE_IN_BYTES: &str = ".usage_in_bytes";
// Maximum recorded memory usage
const MEMORY_MAX_USAGE_IN_BYTES: &str = ".max_usage_in_bytes";
// Memory usage limit in bytes
const MEMORY_LIMIT_IN_BYTES: &str = ".limit_in_bytes";
// Number of times memory usage hit limits
const MEMORY_FAIL_COUNT: &str = ".failcnt";

#[derive(Debug)]
pub enum MalformedThing {
    Limit,
    Usage,
    MaxUsage,
}

impl Display for MalformedThing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MalformedThing::Limit => f.write_str("memory limit"),
            MalformedThing::Usage => f.write_str("memory usage"),
            MalformedThing::MaxUsage => f.write_str("memory max usage"),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V1MemoryControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("invalid swappiness value: {supplied}. valid range is 0-100")]
    SwappinessOutOfRange { supplied: u64 },
    #[error("read malformed {thing} {limit} from {path}: {err}")]
    MalformedValue {
        thing: MalformedThing,
        limit: String,
        path: PathBuf,
        err: ParseIntError,
    },
    #[error(
        "unable to set memory limit to {target} (current usage: {current}, peak usage: {peak})"
    )]
    UnableToSet {
        target: i64,
        current: u64,
        peak: u64,
    },
}

pub struct Memory {}

impl Controller for Memory {
    type Error = V1MemoryControllerError;
    type Resource = LinuxMemory;

    fn apply(
        controller_opt: &ControllerOpt,
        cgroup_root: &Path,
    ) -> Result<(), V1MemoryControllerError> {
        tracing::debug!("Apply Memory cgroup config");

        if let Some(memory) = &controller_opt.resources.memory() {
            let reservation = memory.reservation().unwrap_or(0);

            Self::apply(memory, cgroup_root)?;

            if reservation != 0 {
                common::write_cgroup_file(
                    cgroup_root.join(CGROUP_MEMORY_RESERVATION),
                    reservation,
                )?;
            }

            if controller_opt.disable_oom_killer {
                common::write_cgroup_file(cgroup_root.join(CGROUP_MEMORY_OOM_CONTROL), 0)?;
            } else {
                common::write_cgroup_file(cgroup_root.join(CGROUP_MEMORY_OOM_CONTROL), 1)?;
            }

            if let Some(swappiness) = memory.swappiness() {
                if swappiness <= 100 {
                    common::write_cgroup_file(
                        cgroup_root.join(CGROUP_MEMORY_SWAPPINESS),
                        swappiness,
                    )?;
                } else {
                    // invalid swappiness value
                    return Err(V1MemoryControllerError::SwappinessOutOfRange {
                        supplied: swappiness,
                    });
                }
            }

            // NOTE: Seems as though kernel and kernelTCP are both deprecated
            // neither are implemented by runc. Tests pass without this, but
            // kept in per the spec.
            if let Some(kmem) = memory.kernel() {
                common::write_cgroup_file(cgroup_root.join(CGROUP_KERNEL_MEMORY_LIMIT), kmem)?;
            }
            if let Some(tcp_mem) = memory.kernel_tcp() {
                common::write_cgroup_file(
                    cgroup_root.join(CGROUP_KERNEL_TCP_MEMORY_LIMIT),
                    tcp_mem,
                )?;
            }
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        controller_opt.resources.memory().as_ref()
    }
}
#[derive(thiserror::Error, Debug)]
pub enum V1MemoryStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("error parsing stat data: {0}")]
    Parse(#[from] ParseFlatKeyedDataError),
}

impl StatsProvider for Memory {
    type Error = V1MemoryStatsError;
    type Stats = MemoryStats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let memory = Self::get_memory_data(cgroup_path, MEMORY_PREFIX)?;
        let memswap = Self::get_memory_data(cgroup_path, MEMORY_AND_SWAP_PREFIX)?;
        let kernel = Self::get_memory_data(cgroup_path, MEMORY_KERNEL_PREFIX)?;
        let kernel_tcp = Self::get_memory_data(cgroup_path, MEMORY_KERNEL_TCP_PREFIX)?;
        let hierarchy = Self::hierarchy_enabled(cgroup_path)?;
        let stats = Self::get_stat_data(cgroup_path)?;

        Ok(MemoryStats {
            memory,
            memswap,
            kernel,
            kernel_tcp,
            cache: stats["cache"],
            hierarchy,
            stats,
            ..Default::default()
        })
    }
}

impl Memory {
    fn get_memory_data(
        cgroup_path: &Path,
        file_prefix: &str,
    ) -> Result<MemoryData, WrappedIoError> {
        let memory_data = MemoryData {
            usage: parse_single_value(
                &cgroup_path.join(format!("{file_prefix}{MEMORY_USAGE_IN_BYTES}")),
            )?,
            max_usage: parse_single_value(
                &cgroup_path.join(format!("{file_prefix}{MEMORY_MAX_USAGE_IN_BYTES}")),
            )?,
            limit: parse_single_value(
                &cgroup_path.join(format!("{file_prefix}{MEMORY_LIMIT_IN_BYTES}")),
            )?,
            fail_count: parse_single_value(
                &cgroup_path.join(format!("{file_prefix}{MEMORY_FAIL_COUNT}")),
            )?,
        };

        Ok(memory_data)
    }

    fn hierarchy_enabled(cgroup_path: &Path) -> Result<bool, WrappedIoError> {
        let hierarchy_path = cgroup_path.join(MEMORY_USE_HIERARCHY);
        let hierarchy = common::read_cgroup_file(hierarchy_path)?;
        let enabled = matches!(hierarchy.trim(), "1");

        Ok(enabled)
    }

    fn get_stat_data(cgroup_path: &Path) -> Result<HashMap<String, u64>, ParseFlatKeyedDataError> {
        stats::parse_flat_keyed_data(&cgroup_path.join(MEMORY_STAT))
    }

    fn get_memory_usage(cgroup_root: &Path) -> Result<u64, V1MemoryControllerError> {
        let path = cgroup_root.join(CGROUP_MEMORY_USAGE);
        let mut contents = String::new();
        OpenOptions::new()
            .create(false)
            .read(true)
            .open(&path)
            .wrap_open(&path)?
            .read_to_string(&mut contents)
            .wrap_read(&path)?;

        contents = contents.trim().to_string();

        if contents == "max" {
            return Ok(u64::MAX);
        }

        let val =
            contents
                .parse::<u64>()
                .map_err(|err| V1MemoryControllerError::MalformedValue {
                    thing: MalformedThing::Usage,
                    limit: contents,
                    path,
                    err,
                })?;
        Ok(val)
    }

    fn get_memory_max_usage(cgroup_root: &Path) -> Result<u64, V1MemoryControllerError> {
        let path = cgroup_root.join(CGROUP_MEMORY_MAX_USAGE);
        let mut contents = String::new();
        OpenOptions::new()
            .create(false)
            .read(true)
            .open(&path)
            .wrap_open(&path)?
            .read_to_string(&mut contents)
            .wrap_read(&path)?;

        contents = contents.trim().to_string();

        if contents == "max" {
            return Ok(u64::MAX);
        }

        let val =
            contents
                .parse::<u64>()
                .map_err(|err| V1MemoryControllerError::MalformedValue {
                    thing: MalformedThing::MaxUsage,
                    limit: contents,
                    path,
                    err,
                })?;
        Ok(val)
    }

    fn get_memory_limit(cgroup_root: &Path) -> Result<i64, V1MemoryControllerError> {
        let path = cgroup_root.join(CGROUP_MEMORY_LIMIT);
        let mut contents = String::new();
        OpenOptions::new()
            .create(false)
            .read(true)
            .open(&path)
            .wrap_open(&path)?
            .read_to_string(&mut contents)
            .wrap_read(&path)?;

        contents = contents.trim().to_string();

        if contents == "max" {
            return Ok(i64::MAX);
        }

        let val =
            contents
                .parse::<i64>()
                .map_err(|err| V1MemoryControllerError::MalformedValue {
                    thing: MalformedThing::Limit,
                    limit: contents,
                    path,
                    err,
                })?;
        Ok(val)
    }

    fn set<T: ToString>(val: T, path: &Path) -> Result<(), WrappedIoError> {
        let data = val.to_string();
        OpenOptions::new()
            .create(false)
            .write(true)
            .truncate(true)
            .open(path)
            .wrap_open(path)?
            .write_all(data.as_bytes())
            .wrap_write(path, data)?;
        Ok(())
    }

    fn set_memory(val: i64, cgroup_root: &Path) -> Result<(), V1MemoryControllerError> {
        if val == 0 {
            return Ok(());
        }
        let path = cgroup_root.join(CGROUP_MEMORY_LIMIT);

        match Self::set(val, &path) {
            Ok(_) => Ok(()),
            Err(e) => {
                // we need to look into the raw OS error for an EBUSY status
                match e.inner().raw_os_error() {
                    Some(code) => match Errno::from_raw(code) {
                        Errno::EBUSY => {
                            let usage = Self::get_memory_usage(cgroup_root)?;
                            let max_usage = Self::get_memory_max_usage(cgroup_root)?;
                            Err(V1MemoryControllerError::UnableToSet {
                                target: val,
                                current: usage,
                                peak: max_usage,
                            })
                        }
                        _ => Err(e)?,
                    },
                    None => Err(e)?,
                }
            }
        }
    }

    fn set_swap(swap: i64, cgroup_root: &Path) -> Result<(), V1MemoryControllerError> {
        if swap == 0 {
            return Ok(());
        }

        common::write_cgroup_file(cgroup_root.join(CGROUP_MEMORY_SWAP_LIMIT), swap)?;
        Ok(())
    }

    fn set_memory_and_swap(
        limit: i64,
        swap: i64,
        is_updated: bool,
        cgroup_root: &Path,
    ) -> Result<(), V1MemoryControllerError> {
        // According to runc we need to change the write sequence of
        // limit and swap so it won't fail, because the new and old
        // values don't fit the kernel's validation
        // see:
        // https://github.com/opencontainers/runc/blob/3f6594675675d4e88901c782462f56497260b1d2/libcontainer/cgroups/fs/memory.go#L89
        if is_updated {
            Self::set_swap(swap, cgroup_root)?;
            Self::set_memory(limit, cgroup_root)?;
        }
        Self::set_memory(limit, cgroup_root)?;
        Self::set_swap(swap, cgroup_root)?;
        Ok(())
    }

    fn apply(resource: &LinuxMemory, cgroup_root: &Path) -> Result<(), V1MemoryControllerError> {
        match resource.limit() {
            Some(limit) => {
                let current_limit = Self::get_memory_limit(cgroup_root)?;
                match resource.swap() {
                    Some(swap) => {
                        let is_updated = swap == -1 || current_limit < swap;
                        Self::set_memory_and_swap(limit, swap, is_updated, cgroup_root)?;
                    }
                    None => {
                        if limit == -1 {
                            Self::set_memory_and_swap(limit, -1, true, cgroup_root)?;
                        } else {
                            let is_updated = current_limit < 0;
                            Self::set_memory_and_swap(limit, 0, is_updated, cgroup_root)?;
                        }
                    }
                }
            }
            None => match resource.swap() {
                Some(swap) => Self::set_memory_and_swap(0, swap, false, cgroup_root)?,
                None => Self::set_memory_and_swap(0, 0, false, cgroup_root)?,
            },
        }
        Ok(())
    }
}