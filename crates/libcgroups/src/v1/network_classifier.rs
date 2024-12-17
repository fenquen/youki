use std::path::Path;

use oci_spec::runtime::LinuxNetwork;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};

pub struct NetworkClassifier {}

impl Controller for NetworkClassifier {
    type Error = WrappedIoError;
    type Resource = LinuxNetwork;

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply NetworkClassifier cgroup config");

        if let Some(network) = Self::needs_to_handle(controller_opt) {
            Self::apply(cgroup_root, network)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        controller_opt.resources.network().as_ref()
    }
}

impl NetworkClassifier {
    fn apply(root_path: &Path, network: &LinuxNetwork) -> Result<(), WrappedIoError> {
        if let Some(class_id) = network.class_id() {
            common::write_cgroup_file(root_path.join("net_cls.classid"), class_id)?;
        }

        Ok(())
    }
}
