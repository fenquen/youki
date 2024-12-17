use std::collections::HashMap;
use std::convert::Infallible;

use oci_spec::runtime::LinuxPids;

use super::controller::Controller;
use super::dbus_native::serialize::Variant;
use crate::common::ControllerOpt;

pub const TASKS_MAX: &str = "TasksMax";

pub struct Pids {}

impl Controller for Pids {
    type Error = Infallible;

    fn apply(
        options: &ControllerOpt,
        _: u32,
        properties: &mut HashMap<&str, Variant>,
    ) -> Result<(), Self::Error> {
        if let Some(pids) = options.resources.pids() {
            tracing::debug!("Applying pids resource restrictions");
            Self::apply(pids, properties);
        }

        Ok(())
    }
}

impl Pids {
    fn apply(pids: &LinuxPids, properties: &mut HashMap<&str, Variant>) {
        let limit = if pids.limit() > 0 {
            pids.limit() as u64
        } else {
            u64::MAX
        };

        properties.insert(TASKS_MAX, Variant::U64(limit));
    }
}
