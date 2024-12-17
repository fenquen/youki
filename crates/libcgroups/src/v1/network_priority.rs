use std::path::Path;

use oci_spec::runtime::LinuxNetwork;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};

pub struct NetworkPriority {}

impl Controller for NetworkPriority {
    type Error = WrappedIoError;
    type Resource = LinuxNetwork;

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply NetworkPriority cgroup config");

        if let Some(network) = Self::needs_to_handle(controller_opt) {
            Self::apply(cgroup_root, network)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        controller_opt.resources.network().as_ref()
    }
}

impl NetworkPriority {
    fn apply(root_path: &Path, network: &LinuxNetwork) -> Result<(), WrappedIoError> {
        if let Some(ni_priorities) = network.priorities() {
            let priorities: String = ni_priorities.iter().map(|p| p.to_string()).collect();
            common::write_cgroup_file_str(root_path.join("net_prio.ifpriomap"), priorities.trim())?;
        }

        Ok(())
    }
}