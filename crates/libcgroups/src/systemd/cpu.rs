use std::collections::HashMap;

use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use super::dbus_native::serialize::Variant;
use crate::common::ControllerOpt;

pub const CPU_WEIGHT: &str = "CPUWeight";
pub const CPU_QUOTA: &str = "CPUQuotaPerSecUSec";
pub const CPU_PERIOD: &str = "CPUQuotaPeriodUSec";
const MICROSECS_PER_SEC: u64 = 1_000_000;

#[derive(thiserror::Error, Debug)]
pub enum SystemdCpuError {
    #[error("realtime is not supported on systemd v2 yet")]
    RealtimeSystemd,
}

pub(crate) struct Cpu {}

impl Controller for Cpu {
    type Error = SystemdCpuError;

    fn apply(
        options: &ControllerOpt,
        _: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(cpu) = options.resources.cpu() {
            tracing::debug!("Applying cpu resource restrictions");
            Self::apply(cpu, properties)?;
        }

        Ok(())
    }
}

impl Cpu {
    fn apply(
        cpu: &LinuxCpu,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdCpuError> {
        if Self::is_realtime_requested(cpu) {
            return Err(SystemdCpuError::RealtimeSystemd);
        }

        if let Some(mut shares) = cpu.shares() {
            shares = convert_shares_to_cgroup2(shares);
            if shares != 0 {
                properties.insert(CPU_WEIGHT, Variant::U64(shares));
            }
        }

        // if quota is unrestricted set to 'max'
        let mut quota = u64::MAX;
        if let Some(specified_quota) = cpu.quota() {
            if specified_quota > 0 {
                let period = cpu.period().unwrap_or(100_000);

                // cpu quota in systemd must be specified as number of
                // microseconds per second of cpu time.
                quota = specified_quota as u64 * MICROSECS_PER_SEC / period;
            }
        }
        properties.insert(CPU_QUOTA, Variant::U64(quota));

        let mut period: u64 = 100_000;
        if let Some(specified_period) = cpu.period() {
            if specified_period > 0 {
                period = specified_period;
            }
        }
        properties.insert(CPU_PERIOD, Variant::U64(period));

        Ok(())
    }

    fn is_realtime_requested(cpu: &LinuxCpu) -> bool {
        cpu.realtime_period().is_some() || cpu.realtime_runtime().is_some()
    }
}

pub fn convert_shares_to_cgroup2(shares: u64) -> u64 {
    if shares == 0 {
        return 0;
    }

    1 + ((shares.saturating_sub(2)) * 9999) / 262142
}
