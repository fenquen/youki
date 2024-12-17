use std::path::Path;

use super::controller::Controller;
use crate::common::{ControllerOpt, WrappedIoError};

pub struct PerfEvent {}

impl Controller for PerfEvent {
    type Error = WrappedIoError;
    type Resource = ();

    fn apply(_controller_opt: &ControllerOpt, _cgroup_root: &Path) -> Result<(), Self::Error> {
        Ok(())
    }
    //no need to handle any case
    fn needs_to_handle<'a>(_controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        None
    }
}