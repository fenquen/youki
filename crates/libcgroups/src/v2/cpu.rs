use std::borrow::Cow;
use std::path::{Path, PathBuf};

use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{self, CpuStats, ParseFlatKeyedDataError, StatsProvider};

const CGROUP_CPU_WEIGHT: &str = "cpu.weight";
const CGROUP_CPU_MAX: &str = "cpu.max";
const CGROUP_CPU_BURST: &str = "cpu.max.burst";
const CGROUP_CPU_IDLE: &str = "cpu.idle";
const UNRESTRICTED_QUOTA: &str = "max";
const MAX_CPU_WEIGHT: u64 = 10000;

const CPU_STAT: &str = "cpu.stat";
const CPU_PSI: &str = "cpu.pressure";

#[derive(thiserror::Error, Debug)]
pub enum V2CpuControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("realtime is not supported on v2 yet")]
    RealtimeV2,
}

pub struct Cpu {}

impl Controller for Cpu {
    type Error = V2CpuControllerError;

    fn apply(controller_opt: &ControllerOpt, path: &Path) -> Result<(), Self::Error> {
        if let Some(cpu) = &controller_opt.resources.cpu() {
            Self::apply(path, cpu)?;
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V2CpuStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("while parsing stat table: {0}")]
    ParseNestedKeyedData(#[from] ParseFlatKeyedDataError),
    #[error("missing field {field} from {path}")]
    MissingField { field: &'static str, path: PathBuf },
}

impl StatsProvider for Cpu {
    type Error = V2CpuStatsError;
    type Stats = CpuStats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let mut stats = CpuStats::default();
        let stats_path = cgroup_path.join(CPU_STAT);

        let stats_table = stats::parse_flat_keyed_data(&stats_path)?;

        macro_rules! get {
            ($name: expr => $field1:ident.$field2:ident) => {
                stats.$field1.$field2 =
                    *stats_table
                        .get($name)
                        .ok_or_else(|| V2CpuStatsError::MissingField {
                            field: $name,
                            path: stats_path.clone(),
                        })?;
            };
        }

        get!("usage_usec" => usage.usage_total);
        get!("user_usec" => usage.usage_user);
        get!("system_usec" => usage.usage_kernel);
        get!("nr_periods" => throttling.periods);
        get!("nr_throttled" => throttling.throttled_periods);
        get!("throttled_usec" => throttling.throttled_time);

        stats.psi = stats::psi_stats(&cgroup_path.join(CPU_PSI))?;
        Ok(stats)
    }
}

impl Cpu {
    fn apply(path: &Path, cpu: &LinuxCpu) -> Result<(), V2CpuControllerError> {
        if Self::is_realtime_requested(cpu) {
            return Err(V2CpuControllerError::RealtimeV2);
        }

        if let Some(mut shares) = cpu.shares() {
            shares = Self::convert_shares_to_cgroup2(shares);
            if shares != 0 {
                // will result in Erno 34 (numerical result out of range) otherwise
                common::write_cgroup_file(path.join(CGROUP_CPU_WEIGHT), shares)?;
            }
        }

        let cpu_max_file = path.join(CGROUP_CPU_MAX);
        let new_cpu_max: Option<Cow<str>> = match (cpu.quota(), cpu.period()) {
            (None, Some(period)) => Self::create_period_only_value(&cpu_max_file, period)?,
            (Some(quota), None) if quota > 0 => Some(quota.to_string().into()),
            (Some(quota), None) if quota <= 0 => Some(UNRESTRICTED_QUOTA.into()),
            (Some(quota), Some(period)) if quota > 0 => Some(format!("{quota} {period}").into()),
            (Some(quota), Some(period)) if quota <= 0 => {
                Some(format!("{UNRESTRICTED_QUOTA} {period}").into())
            }
            _ => None,
        };

        // format is 'quota period'
        // the kernel default is 'max 100000'
        // 250000 250000 -> 1 CPU worth of runtime every 250ms
        // 10000 50000 -> 20% of one CPU every 50ms
        if let Some(cpu_max) = new_cpu_max {
            common::write_cgroup_file_str(&cpu_max_file, &cpu_max)?;
        }

        if let Some(burst) = cpu.burst() {
            common::write_cgroup_file(path.join(CGROUP_CPU_BURST), burst)?;
        }

        if let Some(idle) = cpu.idle() {
            common::write_cgroup_file(path.join(CGROUP_CPU_IDLE), idle)?;
        }

        Ok(())
    }

    fn convert_shares_to_cgroup2(shares: u64) -> u64 {
        if shares == 0 {
            return 0;
        }

        let weight = 1 + ((shares.saturating_sub(2)) * 9999) / 262142;
        weight.min(MAX_CPU_WEIGHT)
    }

    fn is_realtime_requested(cpu: &LinuxCpu) -> bool {
        if cpu.realtime_period().is_some() {
            return true;
        }

        if cpu.realtime_runtime().is_some() {
            return true;
        }

        false
    }

    fn create_period_only_value(
        cpu_max_file: &Path,
        period: u64,
    ) -> Result<Option<Cow<str>>, V2CpuControllerError> {
        let old_cpu_max = common::read_cgroup_file(cpu_max_file)?;
        if let Some(old_quota) = old_cpu_max.split_whitespace().next() {
            return Ok(Some(format!("{old_quota} {period}").into()));
        }
        Ok(None)
    }
}
