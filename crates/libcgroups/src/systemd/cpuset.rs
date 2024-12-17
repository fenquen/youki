use std::collections::HashMap;

use fixedbitset::FixedBitSet;
use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use super::dbus_native::serialize::Variant;
use crate::common::ControllerOpt;

pub const ALLOWED_CPUS: &str = "AllowedCPUs";
pub const ALLOWED_NODES: &str = "AllowedMemoryNodes";

#[derive(thiserror::Error, Debug)]
pub enum SystemdCpuSetError {
    #[error("setting cpuset restrictions requires systemd version greater than 243")]
    OldSystemd,
    #[error("could not create bitmask for cpus: {0}")]
    CpusBitmask(BitmaskError),
    #[error("could not create bitmask for memory nodes: {0}")]
    MemoryNodesBitmask(BitmaskError),
}

pub struct CpuSet {}

impl Controller for CpuSet {
    type Error = SystemdCpuSetError;

    fn apply(
        options: &ControllerOpt,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(cpu) = options.resources.cpu() {
            tracing::debug!("Applying cpuset resource restrictions");
            return Self::apply(cpu, systemd_version, properties);
        }

        Ok(())
    }
}

impl CpuSet {
    fn apply(
        cpu: &LinuxCpu,
        systemd_version: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), SystemdCpuSetError> {
        if systemd_version <= 243 {
            return Err(SystemdCpuSetError::OldSystemd);
        }

        if let Some(cpus) = cpu.cpus() {
            let cpu_mask: Vec<_> = to_bitmask(cpus)
                .map_err(SystemdCpuSetError::CpusBitmask)?
                .into_iter()
                .map(|v| v as u64)
                .collect();
            properties.insert(ALLOWED_CPUS, Variant::ArrayU64(cpu_mask));
        }

        if let Some(mems) = cpu.mems() {
            let mems_mask: Vec<_> = to_bitmask(mems)
                .map_err(SystemdCpuSetError::MemoryNodesBitmask)?
                .into_iter()
                .map(|v| v as u64)
                .collect();
            properties.insert(ALLOWED_NODES, Variant::ArrayU64(mems_mask));
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BitmaskError {
    #[error("invalid index {index}: {err}")]
    InvalidIndex {
        err: std::num::ParseIntError,
        index: String,
    },
    #[error("invalid cpu range {0}")]
    InvalidRange(String),
}

pub fn to_bitmask(range: &str) -> Result<Vec<u8>, BitmaskError> {
    let mut bitset = FixedBitSet::with_capacity(8);

    for cpu_set in range.split_terminator(',') {
        let cpu_set = cpu_set.trim();
        if cpu_set.is_empty() {
            continue;
        }

        let cpus: Vec<&str> = cpu_set.split('-').map(|s| s.trim()).collect();
        if cpus.len() == 1 {
            let cpu_index: usize = cpus[0].parse().map_err(|err| BitmaskError::InvalidIndex {
                err,
                index: cpus[0].into(),
            })?;
            if cpu_index >= bitset.len() {
                bitset.grow(bitset.len() + 8);
            }
            bitset.set(cpu_index, true);
        } else {
            let start_index = cpus[0].parse().map_err(|err| BitmaskError::InvalidIndex {
                err,
                index: cpus[0].into(),
            })?;
            let end_index = cpus[1].parse().map_err(|err| BitmaskError::InvalidIndex {
                err,
                index: cpus[1].into(),
            })?;
            if start_index > end_index {
                return Err(BitmaskError::InvalidRange(cpu_set.into()));
            }

            if end_index >= bitset.len() {
                bitset.grow(end_index + 1);
            }

            bitset.set_range(start_index..end_index + 1, true);
        }
    }

    // systemd expects a sequence of bytes with no leading zeros, otherwise the values will not be set
    // with no error message
    Ok(bitset
        .as_slice()
        .iter()
        .flat_map(|b| b.to_be_bytes())
        .skip_while(|b| *b == 0u8)
        .collect())
}
