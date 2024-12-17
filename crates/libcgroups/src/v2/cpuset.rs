use std::path::Path;

use oci_spec::runtime::LinuxCpu;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};

const CGROUP_CPUSET_CPUS: &str = "cpuset.cpus";
const CGROUP_CPUSET_MEMS: &str = "cpuset.mems";

pub struct CpuSet {}

impl Controller for CpuSet {
    type Error = WrappedIoError;

    fn apply(controller_opt: &ControllerOpt, cgroup_path: &Path) -> Result<(), Self::Error> {
        if let Some(cpuset) = &controller_opt.resources.cpu() {
            Self::apply(cgroup_path, cpuset)?;
        }

        Ok(())
    }
}

impl CpuSet {
    fn apply(path: &Path, cpuset: &LinuxCpu) -> Result<(), WrappedIoError> {
        if let Some(cpus) = &cpuset.cpus() {
            common::write_cgroup_file_str(path.join(CGROUP_CPUSET_CPUS), cpus)?;
        }

        if let Some(mems) = &cpuset.mems() {
            common::write_cgroup_file_str(path.join(CGROUP_CPUSET_MEMS), mems)?;
        }

        Ok(())
    }
}
