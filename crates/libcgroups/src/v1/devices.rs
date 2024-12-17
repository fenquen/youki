use std::path::Path;

use oci_spec::runtime::LinuxDeviceCgroup;

use super::controller::Controller;
use crate::common::{self, default_allow_devices, default_devices, ControllerOpt, WrappedIoError};

pub struct Devices {}

impl Controller for Devices {
    type Error = WrappedIoError;
    type Resource = ();

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply Devices cgroup config");

        if let Some(devices) = controller_opt.resources.devices().as_ref() {
            for d in devices {
                Self::apply_device(d, cgroup_root)?;
            }
        }

        for d in [
            default_devices().iter().map(|d| d.into()).collect(),
            default_allow_devices(),
        ]
        .concat()
        {
            Self::apply_device(&d, cgroup_root)?;
        }

        Ok(())
    }

    // always needs to be called due to default devices
    fn needs_to_handle<'a>(_controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        Some(&())
    }
}

impl Devices {
    fn apply_device(device: &LinuxDeviceCgroup, cgroup_root: &Path) -> Result<(), WrappedIoError> {
        let path = if device.allow() {
            cgroup_root.join("devices.allow")
        } else {
            cgroup_root.join("devices.deny")
        };

        common::write_cgroup_file_str(path, &device.to_string())?;
        Ok(())
    }
}
