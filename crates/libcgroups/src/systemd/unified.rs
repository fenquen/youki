use std::collections::HashMap;
use std::num::ParseIntError;

use super::controller::Controller;
use super::cpu::{self, convert_shares_to_cgroup2};
use super::cpuset::{self, to_bitmask, BitmaskError};
use super::dbus_native::serialize::Variant;
use super::{memory, pids};
use crate::common::ControllerOpt;

#[derive(thiserror::Error, Debug)]
pub enum SystemdUnifiedError {
    #[error("failed to parse cpu weight {value}: {err}")]
    CpuWeight { err: ParseIntError, value: String },
    #[error("invalid format for cpu.max: {0}")]
    CpuMax(String),
    #[error("failed to to parse cpu quota {value}: {err}")]
    CpuQuota { err: ParseIntError, value: String },
    #[error("failed to to parse cpu period {value}: {err}")]
    CpuPeriod { err: ParseIntError, value: String },
    #[error("setting {0} requires systemd version greater than 243")]
    OldSystemd(String),
    #[error("invalid value for cpuset.cpus {0}")]
    CpuSetCpu(BitmaskError),
    #[error("failed to parse {name} {value}: {err}")]
    Memory {
        err: ParseIntError,
        name: String,
        value: String,
    },
    #[error("failed to to parse pids.max {value}: {err}")]
    PidsMax { err: ParseIntError, value: String },
}

pub struct Unified {}

impl Controller for Unified {
    type Error = SystemdUnifiedError;

    fn apply(
        options: &ControllerOpt,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(unified) = options.resources.unified() {
            tracing::debug!("applying unified resource restrictions");
            Self::apply(unified, systemd_version, properties)?;
        }

        Ok(())
    }
}

impl Unified {
    fn apply(
        unified: &HashMap<String, String>,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdUnifiedError> {
        for (key, value) in unified {
            match key.as_str() {
                "cpu.weight" => {
                    let shares =
                        value
                            .parse::<u64>()
                            .map_err(|err| SystemdUnifiedError::CpuWeight {
                                err,
                                value: value.into(),
                            })?;
                    properties.insert(
                        cpu::CPU_WEIGHT,
                        Variant::U64(convert_shares_to_cgroup2(shares)),
                    );
                }
                "cpu.max" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.is_empty() || parts.len() > 2 {
                        return Err(SystemdUnifiedError::CpuMax(value.into()));
                    }

                    let quota =
                        parts[0]
                            .parse::<u64>()
                            .map_err(|err| SystemdUnifiedError::CpuQuota {
                                err,
                                value: parts[0].into(),
                            })?;
                    properties.insert(cpu::CPU_QUOTA, Variant::U64(quota));

                    if parts.len() == 2 {
                        let period = parts[1].parse::<u64>().map_err(|err| {
                            SystemdUnifiedError::CpuPeriod {
                                err,
                                value: parts[1].into(),
                            }
                        })?;
                        properties.insert(cpu::CPU_PERIOD, Variant::U64(period));
                    }
                }
                cpuset @ ("cpuset.cpus" | "cpuset.mems") => {
                    if systemd_version <= 243 {
                        return Err(SystemdUnifiedError::OldSystemd(cpuset.into()));
                    }

                    let bitmask: Vec<u64> = to_bitmask(value)
                        .map_err(SystemdUnifiedError::CpuSetCpu)?
                        .into_iter()
                        .map(|v| v as u64)
                        .collect();

                    let systemd_cpuset = match cpuset {
                        "cpuset.cpus" => cpuset::ALLOWED_CPUS,
                        "cpuset.mems" => cpuset::ALLOWED_NODES,
                        file_name => unreachable!("{} was not matched", file_name),
                    };

                    properties.insert(systemd_cpuset, Variant::ArrayU64(bitmask));
                }
                memory @ ("memory.min" | "memory.low" | "memory.high" | "memory.max") => {
                    let value =
                        value
                            .parse::<u64>()
                            .map_err(|err| SystemdUnifiedError::Memory {
                                err,
                                name: memory.into(),
                                value: value.into(),
                            })?;
                    let systemd_memory = match memory {
                        "memory.min" => memory::MEMORY_MIN,
                        "memory.low" => memory::MEMORY_LOW,
                        "memory.high" => memory::MEMORY_HIGH,
                        "memory.max" => memory::MEMORY_MAX,
                        file_name => unreachable!("{} was not matched", file_name),
                    };
                    properties.insert(systemd_memory, Variant::U64(value));
                }
                "pids.max" => {
                    let pids = value.trim().parse::<i64>().map_err(|err| {
                        SystemdUnifiedError::PidsMax {
                            err,
                            value: value.into(),
                        }
                    })?;
                    properties.insert(pids::TASKS_MAX, Variant::U64(pids as u64));
                }

                unknown => tracing::warn!("could not apply {}. Unknown property.", unknown),
            }
        }

        Ok(())
    }
}
