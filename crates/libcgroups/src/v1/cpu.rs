use std::path::{Path, PathBuf};

use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{parse_flat_keyed_data, CpuThrottling, ParseFlatKeyedDataError, StatsProvider};

const CGROUP_CPU_SHARES: &str = "cpu.shares";
const CGROUP_CPU_QUOTA: &str = "cpu.cfs_quota_us";
const CGROUP_CPU_PERIOD: &str = "cpu.cfs_period_us";
const CGROUP_CPU_BURST: &str = "cpu.cfs_burst_us";
const CGROUP_CPU_RT_RUNTIME: &str = "cpu.rt_runtime_us";
const CGROUP_CPU_RT_PERIOD: &str = "cpu.rt_period_us";
const CGROUP_CPU_STAT: &str = "cpu.stat";
const CGROUP_CPU_IDLE: &str = "cpu.idle";

pub struct Cpu {}

impl Controller for Cpu {
    type Error = WrappedIoError;
    type Resource = LinuxCpu;

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply Cpu cgroup config");

        if let Some(cpu) = Self::needs_to_handle(controller_opt) {
            Self::apply(cgroup_root, cpu)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        if let Some(cpu) = &controller_opt.resources.cpu() {
            if cpu.shares().is_some()
                || cpu.period().is_some()
                || cpu.quota().is_some()
                || cpu.realtime_period().is_some()
                || cpu.realtime_runtime().is_some()
                || cpu.idle().is_some()
            {
                return Some(cpu);
            }
        }

        None
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V1CpuStatsError {
    #[error("error parsing data: {0}")]
    ParseData(#[from] ParseFlatKeyedDataError),
    #[error("missing field {field} from {path}")]
    MissingField { field: &'static str, path: PathBuf },
}

impl StatsProvider for Cpu {
    type Error = V1CpuStatsError;
    type Stats = CpuThrottling;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let mut stats = CpuThrottling::default();
        let stat_path = cgroup_path.join(CGROUP_CPU_STAT);

        let stat_table = parse_flat_keyed_data(&stat_path)?;

        macro_rules! get {
            ($name: expr => $field: ident) => {
                stats.$field =
                    *stat_table
                        .get($name)
                        .ok_or_else(|| V1CpuStatsError::MissingField {
                            field: $name,
                            path: stat_path.clone(),
                        })?;
            };
        }

        get!("nr_periods" => periods);
        get!("nr_throttled" => throttled_periods);
        get!("throttled_time" => throttled_time);

        Ok(stats)
    }
}

impl Cpu {
    fn apply(root_path: &Path, cpu: &LinuxCpu) -> Result<(), WrappedIoError> {
        if let Some(cpu_shares) = cpu.shares() {
            if cpu_shares != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_SHARES), cpu_shares)?;
            }
        }

        if let Some(cpu_period) = cpu.period() {
            if cpu_period != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_PERIOD), cpu_period)?;
            }
        }

        if let Some(cpu_quota) = cpu.quota() {
            if cpu_quota != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_QUOTA), cpu_quota)?;
            }
        }

        if let Some(cpu_burst) = cpu.burst() {
            common::write_cgroup_file(root_path.join(CGROUP_CPU_BURST), cpu_burst)?;
        }

        if let Some(rt_runtime) = cpu.realtime_runtime() {
            if rt_runtime != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_RT_RUNTIME), rt_runtime)?;
            }
        }

        if let Some(rt_period) = cpu.realtime_period() {
            if rt_period != 0 {
                common::write_cgroup_file(root_path.join(CGROUP_CPU_RT_PERIOD), rt_period)?;
            }
        }

        if let Some(idle) = cpu.idle() {
            common::write_cgroup_file(root_path.join(CGROUP_CPU_IDLE), idle)?;
        }

        Ok(())
    }
}