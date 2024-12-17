use std::collections::HashMap;
use std::path::Path;

use super::controller_type::ControllerType;
use crate::common::{self, ControllerOpt, WrappedIoError};

#[derive(thiserror::Error, Debug)]
pub enum V2UnifiedError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("subsystem {subsystem} is not available: {err}")]
    SubsystemNotAvailable {
        subsystem: String,
        err: WrappedIoError,
    },
}

pub struct Unified {}

impl Unified {
    pub fn apply(
        controller_opt: &ControllerOpt,
        cgroup_path: &Path,
        controllers: Vec<ControllerType>,
    ) -> Result<(), V2UnifiedError> {
        if let Some(unified) = &controller_opt.resources.unified() {
            Self::apply_impl(unified, cgroup_path, &controllers)?;
        }

        Ok(())
    }

    fn apply_impl(
        unified: &HashMap<String, String>,
        cgroup_path: &Path,
        controllers: &[ControllerType],
    ) -> Result<(), V2UnifiedError> {
        tracing::debug!("Apply unified cgroup config");
        for (cgroup_file, value) in unified {
            if let Err(err) = common::write_cgroup_file_str(cgroup_path.join(cgroup_file), value) {
                let (subsystem, _) = cgroup_file.split_once('.').unwrap_or((cgroup_file, ""));

                if controllers.iter().any(|c| c.to_string() == subsystem) {
                    Err(err)?;
                } else {
                    return Err(V2UnifiedError::SubsystemNotAvailable {
                        subsystem: subsystem.into(),
                        err,
                    });
                }
            }
        }

        Ok(())
    }
}