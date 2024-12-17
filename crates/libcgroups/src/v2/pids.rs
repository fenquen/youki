use std::path::Path;

use oci_spec::runtime::LinuxPids;

use super::controller::Controller;
use crate::common::{self, ControllerOpt, WrappedIoError};
use crate::stats::{self, PidStats, PidStatsError, StatsProvider};

pub struct Pids {}

impl Controller for Pids {
    type Error = WrappedIoError;

    fn apply(
        controller_opt: &ControllerOpt,
        cgroup_root: &std::path::Path,
    ) -> Result<(), Self::Error> {
        tracing::debug!("Apply pids cgroup v2 config");
        if let Some(pids) = &controller_opt.resources.pids() {
            Self::apply(cgroup_root, pids)?;
        }
        Ok(())
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
        common::write_cgroup_file(root_path.join("pids.max"), limit)
    }
}
