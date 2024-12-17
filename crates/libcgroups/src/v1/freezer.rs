use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::{thread, time};

use super::controller::Controller;
use crate::common::{self, ControllerOpt, FreezerState, WrapIoResult, WrappedIoError};

const CGROUP_FREEZER_STATE: &str = "freezer.state";
const FREEZER_STATE_THAWED: &str = "THAWED";
const FREEZER_STATE_FROZEN: &str = "FROZEN";
const FREEZER_STATE_FREEZING: &str = "FREEZING";

#[derive(thiserror::Error, Debug)]
pub enum V1FreezerControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("unexpected state {state} while freezing")]
    UnexpectedState { state: String },
    #[error("unable to freeze")]
    UnableToFreeze,
}

pub struct Freezer {}

impl Controller for Freezer {
    type Error = V1FreezerControllerError;
    type Resource = FreezerState;

    fn apply(controller_opt: &ControllerOpt, cgroup_root: &Path) -> Result<(), Self::Error> {
        tracing::debug!("Apply Freezer cgroup config");
        std::fs::create_dir_all(cgroup_root).wrap_create_dir(cgroup_root)?;

        if let Some(freezer_state) = Self::needs_to_handle(controller_opt) {
            Self::apply(freezer_state, cgroup_root)?;
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        controller_opt.freezer_state.as_ref()
    }
}

impl Freezer {
    fn apply(
        freezer_state: &FreezerState,
        cgroup_root: &Path,
    ) -> Result<(), V1FreezerControllerError> {
        match freezer_state {
            FreezerState::Undefined => {}
            FreezerState::Thawed => {
                common::write_cgroup_file(
                    cgroup_root.join(CGROUP_FREEZER_STATE),
                    FREEZER_STATE_THAWED,
                )?;
            }
            FreezerState::Frozen => {
                let r = || -> Result<(), V1FreezerControllerError> {
                    // We should do our best to retry if FREEZING is seen until it becomes FROZEN.
                    // Add sleep between retries occasionally helped when system is extremely slow.
                    // see:
                    // https://github.com/opencontainers/runc/blob/b9ee9c6314599f1b4a7f497e1f1f856fe433d3b7/libcontainer/cgroups/fs/freezer.go#L42
                    for i in 0..1000 {
                        if i % 50 == 49 {
                            let _ = common::write_cgroup_file(
                                cgroup_root.join(CGROUP_FREEZER_STATE),
                                FREEZER_STATE_THAWED,
                            );
                            thread::sleep(time::Duration::from_millis(10));
                        }

                        common::write_cgroup_file(
                            cgroup_root.join(CGROUP_FREEZER_STATE),
                            FREEZER_STATE_FROZEN,
                        )?;

                        if i % 25 == 24 {
                            thread::sleep(time::Duration::from_millis(10));
                        }

                        let r = Self::read_freezer_state(cgroup_root)?;
                        match r.trim() {
                            FREEZER_STATE_FREEZING => {
                                continue;
                            }
                            FREEZER_STATE_FROZEN => {
                                if i > 1 {
                                    tracing::debug!("frozen after {} retries", i)
                                }
                                return Ok(());
                            }
                            _ => {
                                // should not reach here.
                                return Err(V1FreezerControllerError::UnexpectedState { state: r });
                            }
                        }
                    }
                    Err(V1FreezerControllerError::UnableToFreeze)
                }();

                if r.is_err() {
                    // Freezing failed, and it is bad and dangerous to leave the cgroup in FROZEN or
                    // FREEZING, so try to thaw it back.
                    let _ = common::write_cgroup_file(
                        cgroup_root.join(CGROUP_FREEZER_STATE),
                        FREEZER_STATE_THAWED,
                    );
                }
                return r;
            }
        }
        Ok(())
    }

    fn read_freezer_state(cgroup_root: &Path) -> Result<String, WrappedIoError> {
        let path = cgroup_root.join(CGROUP_FREEZER_STATE);
        let mut content = String::new();
        OpenOptions::new()
            .create(false)
            .read(true)
            .open(path)
            .wrap_open(cgroup_root)?
            .read_to_string(&mut content)
            .wrap_read(cgroup_root)?;
        Ok(content)
    }
}