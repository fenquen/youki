use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use crate::process::args::ContainerArgs;
use crate::process::clone::{self, CloneCb};
use crate::process::intel_rdt::setup_intel_rdt;
use crate::process::{channel, intermediate};
use crate::syscall::SyscallError;
use crate::user_ns::UserNsCfg;

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error(transparent)]
    Channel(#[from] channel::ChannelError),
    #[error("failed to write deny to setgroups")]
    SetGroupsDeny(#[source] std::io::Error),
    #[error(transparent)]
    UserNamespace(#[from] crate::user_ns::UserNamespaceError),
    #[error("container state is required")]
    ContainerStateRequired,
    #[error("failed to wait for intermediate process")]
    WaitIntermediateProcess(#[source] nix::Error),
    #[error(transparent)]
    IntelRdt(#[from] crate::process::intel_rdt::IntelRdtError),
    #[error("failed to create intermediate process")]
    IntermediateProcessFailed(#[source] clone::CloneError),
    #[error("failed seccomp listener")]
    #[cfg(feature = "libseccomp")]
    SeccompListener(#[from] crate::process::seccomp_listener::SeccompListenerError),
    #[error("failed syscall")]
    SyscallOther(#[source] SyscallError),
}

type Result<T> = std::result::Result<T, ProcessError>;

pub fn container_main_process(container_args: &ContainerArgs) -> Result<(Pid, bool)> {
    // We use a set of channels to communicate between parent and child process.
    // Each channel is uni-directional. Because we will pass these channel to
    // cloned process, we have to be deligent about closing any unused channel.
    // At minimum, we have to close down any unused senders. The corresponding
    // receivers will be cleaned up once the senders are closed down.
    let (mut main_sender, mut main_receiver) = channel::main_channel()?;
    let mut inter_chan = channel::intermediate_channel()?;
    let mut init_chan = channel::init_channel()?;

    let cb: CloneCb = Box::new(|| {
        if let Err(ret) = prctl::set_name("youki:[1:INTER]") {
            tracing::error!(?ret, "failed to set name for child process");
            return ret;
        }

        match intermediate::container_intermediate_process(container_args,
                                                           &mut inter_chan,
                                                           &mut init_chan,
                                                           &mut main_sender) {
            Ok(_) => 0,
            Err(err) => {
                tracing::error!("failed to run intermediate process {}", err);
                match main_sender.send_error(err.to_string()) {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("error in sending intermediate error message {} to main: {}", err, e)
                    }
                }
                -1
            }
        }
    });

    // Before starting the intermediate process, mark all non-stdio open files as O_CLOEXEC
    // to ensure we don't leak any file descriptors to the intermediate process.
    // Please refer to https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv for more details.
    let syscall = container_args.syscall.create_syscall();
    syscall.close_range(0).map_err(|err| {
        tracing::error!(?err, "failed to cleanup extra fds");
        ProcessError::SyscallOther(err)
    })?;

    let intermediatePid = clone::container_clone(cb).map_err(|err| {
        tracing::error!("failed to fork intermediate process: {}", err);
        ProcessError::IntermediateProcessFailed(err)
    })?;

    // Close down unused fds. The corresponding fds are duplicated to the child process during clone.
    main_sender.close().map_err(|err| {
        tracing::error!("failed to close unused sender: {}", err);
        err
    })?;

    let (mut inter_sender, inter_receiver) = inter_chan;
    #[cfg(feature = "libseccomp")]
    let (mut init_sender, init_receiver) = init_chan;
    #[cfg(not(feature = "libseccomp"))]
    let (init_sender, init_receiver) = init_chan;

    // If creating a container with new user namespace, the intermediate process will ask
    // the main process to set up uid and gid mapping, once the intermediate
    // process enters into a new user namespace.
    if let Some(config) = &container_args.user_ns_config {
        main_receiver.wait_for_mapping_request()?;
        setup_mapping(config, intermediatePid)?;
        inter_sender.mapping_written()?;
    }

    // At this point, we don't need to send any message to intermediate process anymore,
    // so we want to close this sender at the earliest point.
    inter_sender.close().map_err(|err| {
        tracing::error!("failed to close unused intermediate sender: {}", err);
        err
    })?;

    // The intermediate process will send the init pid once it forks the init
    // process.  The intermediate process should exit after this point.
    let initPid = main_receiver.wait_for_intermediate_ready()?;
    let mut need_to_clean_up_intel_rdt_subdirectory = false;

    if let Some(linux) = container_args.spec.linux() {
        #[cfg(feature = "libseccomp")]
        if let Some(seccomp) = linux.seccomp() {
            let state = crate::container::ContainerProcessState {
                oci_version: container_args.spec.version().to_string(),
                // runc hardcode the `seccompFd` name for fds.
                fds: vec![String::from("seccompFd")],
                pid: initPid.as_raw(),
                metadata: seccomp.listener_metadata().to_owned().unwrap_or_default(),
                state: container_args
                    .container
                    .as_ref()
                    .ok_or(ProcessError::ContainerStateRequired)?
                    .state
                    .clone(),
            };
            crate::process::seccomp_listener::sync_seccomp(
                seccomp,
                &state,
                &mut init_sender,
                &mut main_receiver,
            )?;
        }

        if let Some(intel_rdt) = linux.intel_rdt() {
            let container_id = container_args.container.as_ref().map(|container| container.id());
            need_to_clean_up_intel_rdt_subdirectory =
                setup_intel_rdt(container_id, &initPid, intel_rdt)?;
        }
    }

    // We don't need to send anything to the init process after this point, so
    // close the sender.
    init_sender.close().map_err(|err| {
        tracing::error!("failed to close unused init sender: {}", err);
        err
    })?;

    main_receiver.wait_for_init_ready().map_err(|err| {
        tracing::error!("failed to wait for init ready: {}", err);
        err
    })?;

    tracing::debug!("init pid is {:?}", initPid);

    // Close the receiver ends to avoid leaking file descriptors.

    inter_receiver.close().map_err(|err| {
        tracing::error!("failed to close intermediate process receiver: {}", err);
        err
    })?;

    init_receiver.close().map_err(|err| {
        tracing::error!("failed to close init process receiver: {}", err);
        err
    })?;

    main_receiver.close().map_err(|err| {
        tracing::error!("failed to close main process receiver: {}", err);
        err
    })?;

    // Before the main process returns, we want to make sure the intermediate
    // process is exit and reaped. By this point, the intermediate process
    // should already exited successfully. If intermediate process errors out,
    // the `init_ready` will not be sent.
    match waitpid(intermediatePid, None) {
        Ok(WaitStatus::Exited(_, 0)) => (),
        Ok(WaitStatus::Exited(_, s)) => {
            tracing::warn!("intermediate process failed with exit status: {s}");
        }
        Ok(WaitStatus::Signaled(_, sig, _)) => {
            tracing::warn!("intermediate process killed with signal: {sig}")
        }
        Ok(_) => (),
        Err(nix::errno::Errno::ECHILD) => {
            // This is safe because intermediate_process and main_process check if the process is
            // finished by piping instead of exit code.
            tracing::warn!("intermediate process already reaped");
        }
        Err(err) => return Err(ProcessError::WaitIntermediateProcess(err)),
    };

    Ok((initPid, need_to_clean_up_intel_rdt_subdirectory))
}

fn setup_mapping(config: &UserNsCfg, pid: Pid) -> Result<()> {
    tracing::debug!("write mapping for pid {:?}", pid);
    if !config.privileged {
        // The main process is running as an unprivileged user and cannot write the mapping
        // until "deny" has been written to setgroups. See CVE-2014-8989.
        std::fs::write(format!("/proc/{pid}/setgroups"), "deny")
            .map_err(ProcessError::SetGroupsDeny)?;
    }

    config.write_uid_mapping(pid).map_err(|err| {
        tracing::error!("failed to write uid mapping for pid {:?}: {}", pid, err);
        err
    })?;
    config.write_gid_mapping(pid).map_err(|err| {
        tracing::error!("failed to write gid mapping for pid {:?}: {}", pid, err);
        err
    })?;
    Ok(())
}