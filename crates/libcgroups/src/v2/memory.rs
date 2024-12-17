use std::path::Path;

use oci_spec::runtime::LinuxMemory;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{self, MemoryData, MemoryStats, ParseFlatKeyedDataError, StatsProvider};

const CGROUP_MEMORY_SWAP: &str = "memory.swap.max";
const CGROUP_MEMORY_MAX: &str = "memory.max";
const CGROUP_MEMORY_LOW: &str = "memory.low";
const MEMORY_STAT: &str = "memory.stat";
const MEMORY_PSI: &str = "memory.pressure";

#[derive(thiserror::Error, Debug)]
pub enum V2MemoryControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("invalid memory value {0}")]
    MemoryValue(i64),
    #[error("invalid swap value {0}")]
    SwapValue(i64),
    #[error("swap memory ({swap}) should be bigger than memory limit ({limit})")]
    SwapTooSmall { swap: i64, limit: i64 },
    #[error("unable to set swap limit without memory limit")]
    SwapWithoutLimit,
    #[error("invalid memory reservation value: {0}")]
    MemoryReservation(i64),
}

pub struct Memory {}

impl Controller for Memory {
    type Error = V2MemoryControllerError;

    fn apply(controller_opt: &ControllerOpt, cgroup_path: &Path) -> Result<(), Self::Error> {
        if let Some(memory) = &controller_opt.resources.memory() {
            Self::apply(cgroup_path, memory)?;
        }

        Ok(())
    }
}
#[derive(thiserror::Error, Debug)]
pub enum V2MemoryStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("while parsing stat table: {0}")]
    ParseNestedKeyedData(#[from] ParseFlatKeyedDataError),
}

impl StatsProvider for Memory {
    type Error = V2MemoryStatsError;
    type Stats = MemoryStats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let stats = MemoryStats {
            memory: Self::get_memory_data(cgroup_path, "memory", "oom")?,
            memswap: Self::get_memory_data(cgroup_path, "memory.swap", "fail")?,
            hierarchy: true,
            stats: stats::parse_flat_keyed_data(&cgroup_path.join(MEMORY_STAT))?,
            psi: stats::psi_stats(&cgroup_path.join(MEMORY_PSI))?,
            ..Default::default()
        };

        Ok(stats)
    }
}

impl Memory {
    fn get_memory_data(
        cgroup_path: &Path,
        file_prefix: &str,
        fail_event: &str,
    ) -> Result<MemoryData, V2MemoryStatsError> {
        let usage =
            stats::parse_single_value(&cgroup_path.join(format!("{}.{}", file_prefix, "current")))?;
        let limit =
            stats::parse_single_value(&cgroup_path.join(format!("{}.{}", file_prefix, "max")))?;
        let max_usage =
            stats::parse_single_value(&cgroup_path.join(format!("{}.{}", file_prefix, "peak")))
                .unwrap_or(0);

        let events = stats::parse_flat_keyed_data(
            &cgroup_path.join(format!("{}.{}", file_prefix, "events")),
        )?;
        let fail_count = if let Some((_, v)) = events.get_key_value(fail_event) {
            *v
        } else {
            Default::default()
        };

        Ok(MemoryData {
            usage,
            max_usage,
            fail_count,
            limit,
        })
    }

    fn set<P: AsRef<Path>>(path: P, val: i64) -> Result<(), WrappedIoError> {
        if val == 0 {
            Ok(())
        } else if val == -1 {
            Ok(common::write_cgroup_file_str(path, "max")?)
        } else {
            Ok(common::write_cgroup_file(path, val)?)
        }
    }

    fn apply(path: &Path, memory: &LinuxMemory) -> Result<(), V2MemoryControllerError> {
        // if nothing is set just exit right away
        if memory.reservation().is_none() && memory.limit().is_none() && memory.swap().is_none() {
            return Ok(());
        }

        match memory.limit() {
            Some(limit) if limit < -1 => {
                return Err(V2MemoryControllerError::MemoryValue(limit));
            }
            Some(limit) => match memory.swap() {
                Some(swap) if swap < -1 => {
                    return Err(V2MemoryControllerError::SwapValue(swap));
                }
                Some(swap) => {
                    // -1 means max
                    if swap == -1 || limit == -1 {
                        Memory::set(path.join(CGROUP_MEMORY_SWAP), swap)?;
                    } else {
                        if swap < limit {
                            return Err(V2MemoryControllerError::SwapTooSmall { swap, limit });
                        }

                        // In cgroup v1 swap is memory+swap, but in cgroup v2 swap is
                        // a separate value, so the swap value in the runtime spec needs
                        // to be converted from the cgroup v1 value to the cgroup v2 value
                        // by subtracting limit from swap
                        Memory::set(path.join(CGROUP_MEMORY_SWAP), swap - limit)?;
                    }
                    Memory::set(path.join(CGROUP_MEMORY_MAX), limit)?;
                }
                None => {
                    if limit == -1 {
                        Memory::set(path.join(CGROUP_MEMORY_SWAP), -1)?;
                    }
                    Memory::set(path.join(CGROUP_MEMORY_MAX), limit)?;
                }
            },
            None => {
                if memory.swap().is_some() {
                    return Err(V2MemoryControllerError::SwapWithoutLimit);
                }
            }
        };

        if let Some(reservation) = memory.reservation() {
            if reservation < -1 {
                return Err(V2MemoryControllerError::MemoryReservation(reservation));
            }
            Memory::set(path.join(CGROUP_MEMORY_LOW), reservation)?;
        }

        Ok(())
    }
}