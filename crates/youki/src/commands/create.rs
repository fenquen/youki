//! Handles the creation of a new container
use std::path::PathBuf;

use anyhow::Result;
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use liboci_cli::Create;

use crate::workload::executor::default_executor;

// One thing to note is that in the end, container is just another process in Linux
// it has specific/different control group, namespace, using which program executing in it
// can be given impression that is is running on a complete system, but on the system which
// it is running, it is just another process, and has attributes such as pid, file descriptors, etc.
// associated with it like any other process.
pub fn create(create: Create, root_path: PathBuf, systemd_cgroup: bool) -> Result<()> {
    ContainerBuilder::new(create.container_id.clone(), SyscallType::default())
        .with_executor(default_executor())
        .with_pid_file(create.pid_file.as_ref())?
        .with_console_socket(create.console_socket.as_ref())
        .with_root_path(root_path)? // /run/user/1000/youki
        .with_preserved_fds(create.preserve_fds)
        .validate_id()?
        .as_init(&create.bundle)
        .with_systemd(systemd_cgroup)
        .with_detach(true)
        .build()?;

    Ok(())
}
