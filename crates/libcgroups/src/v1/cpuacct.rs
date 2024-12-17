use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{parse_flat_keyed_data, CpuUsage, ParseFlatKeyedDataError, StatsProvider};

// Contains user mode and kernel mode cpu consumption
const CGROUP_CPUACCT_STAT: &str = "cpuacct.stat";
// Contains overall cpu consumption
const CGROUP_CPUACCT_USAGE: &str = "cpuacct.usage";
// Contains user mode and kernel mode cpu consumption differentiated by core
const CGROUP_CPUACCT_USAGE_ALL: &str = "cpuacct.usage_all";
// Contains overall cpu consumption differentiated by core
const CGROUP_CPUACCT_PERCPU: &str = "cpuacct.usage_percpu";

pub struct CpuAcct {}

impl Controller for CpuAcct {
    type Error = WrappedIoError;
    type Resource = ();

    fn apply(_controller_opt: &ControllerOpt, _cgroup_path: &Path) -> Result<(), Self::Error> {
        Ok(())
    }

    fn needs_to_handle<'a>(_controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        None
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V1CpuAcctStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("error parsing data: {0}")]
    ParseData(#[from] ParseFlatKeyedDataError),
    #[error("missing field {field} from {path}")]
    MissingField { field: &'static str, path: PathBuf },
    #[error("failed to parse total cpu usage: {0}")]
    ParseTotalCpu(ParseIntError),
    #[error("failed to parse per core {mode} mode cpu usage in {path}: {err}")]
    FailedToParseField {
        mode: &'static str,
        path: PathBuf,
        err: ParseIntError,
    },
    #[error("failed to parse per core cpu usage: {0}")]
    ParsePerCore(ParseIntError),
}

impl StatsProvider for CpuAcct {
    type Error = V1CpuAcctStatsError;
    type Stats = CpuUsage;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, V1CpuAcctStatsError> {
        let mut stats = CpuUsage::default();
        Self::get_total_cpu_usage(cgroup_path, &mut stats)?;
        Self::get_per_core_usage(cgroup_path, &mut stats)?;

        Ok(stats)
    }
}

impl CpuAcct {
    fn get_total_cpu_usage(
        cgroup_path: &Path,
        stats: &mut CpuUsage,
    ) -> Result<(), V1CpuAcctStatsError> {
        let stat_file_path = cgroup_path.join(CGROUP_CPUACCT_STAT);
        let stat_table = parse_flat_keyed_data(&stat_file_path)?;

        macro_rules! get {
            ($name: expr => $field: ident) => {
                stats.$field =
                    *stat_table
                        .get($name)
                        .ok_or_else(|| V1CpuAcctStatsError::MissingField {
                            field: $name,
                            path: stat_file_path.clone(),
                        })?;
            };
        }

        get!("user" => usage_user);
        get!("system" => usage_kernel);

        let total = common::read_cgroup_file(cgroup_path.join(CGROUP_CPUACCT_USAGE))?;
        stats.usage_total = total
            .trim()
            .parse()
            .map_err(V1CpuAcctStatsError::ParseTotalCpu)?;

        Ok(())
    }

    fn get_per_core_usage(
        cgroup_path: &Path,
        stats: &mut CpuUsage,
    ) -> Result<(), V1CpuAcctStatsError> {
        let path = cgroup_path.join(CGROUP_CPUACCT_USAGE_ALL);
        let all_content = common::read_cgroup_file(&path)?;
        // first line is header, skip it
        for entry in all_content.lines().skip(1) {
            let entry_parts: Vec<&str> = entry.split_ascii_whitespace().collect();
            if entry_parts.len() != 3 {
                continue;
            }

            stats
                .per_core_usage_user
                .push(entry_parts[1].parse().map_err(|err| {
                    V1CpuAcctStatsError::FailedToParseField {
                        mode: "user",
                        path: path.clone(),
                        err,
                    }
                })?);
            stats
                .per_core_usage_kernel
                .push(entry_parts[2].parse().map_err(|err| {
                    V1CpuAcctStatsError::FailedToParseField {
                        mode: "kernel",
                        path: path.clone(),
                        err,
                    }
                })?);
        }

        let percpu_content = common::read_cgroup_file(cgroup_path.join(CGROUP_CPUACCT_PERCPU))?;
        stats.per_core_usage_total = percpu_content
            .split_ascii_whitespace()
            .map(|v| v.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(V1CpuAcctStatsError::ParsePerCore)?;

        Ok(())
    }
}