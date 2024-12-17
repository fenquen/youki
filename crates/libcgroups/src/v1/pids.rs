use std::path::Path;

use oci_spec::runtime::LinuxPids;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{self, PidStats, PidStatsError, StatsProvider};

// Contains the maximum allowed number of active pids
const CGROUP_PIDS_MAX: &str = "pids.max";

pub struct Pids {}

impl Controller for Pids {
    type Error = WrappedIoError;
    type Resource = LinuxPids;

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply pids cgroup config");

        if let Some(pids) = &controller_opt.resources.pids() {
            Self::apply(cgroup_root, pids)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        controller_opt.resources.pids().as_ref()
    }
}

impl StatsProvider for Pids {
    type Error = PidStatsError;
    type Stats = PidStats;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        stats::pid_stats(cgroup_path)
    }
}

impl Pids {
    fn apply(root_path: &Path, pids: &LinuxPids) -> Result<(), WrappedIoError> {
        let limit = if pids.limit() > 0 {
            pids.limit().to_string()
        } else {
            "max".to_string()
        };

        common::write_cgroup_file_str(root_path.join(CGROUP_PIDS_MAX), &limit)?;
        Ok(())
    }
}