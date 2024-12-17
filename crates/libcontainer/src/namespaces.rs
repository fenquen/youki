//! Namespaces provide isolation of resources for processes at a kernel level.
//! The namespaces are: Mount (filesystem),
//! Process (processes in a namespace have two PIDs, one for the global PID,
//! which is used by the main system and the second one is for the child within the process tree),
//! Interprocess Communication (Control or communication between processes),
//! Network (which network devices can be seen by the processes in the namespace), User (User configs),
//! UTS (hostname and domain information, processes will think they're running on servers with different names),
//! Cgroup (Resource limits, execution priority etc.)

use std::collections::HashMap;

use nix::sched::CloneFlags;
use nix::sys::stat;
use nix::{fcntl, unistd};
use oci_spec::runtime::{LinuxNamespace, LinuxNamespaceType};

use crate::syscall::syscall::create_syscall;
use crate::syscall::Syscall;

type Result<T> = std::result::Result<T, NamespaceError>;

#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Syscall(#[from] crate::syscall::SyscallError),
    #[error("Namespace type not supported: {0}")]
    NotSupported(String),
}

static ORDERED_NAMESPACES: &[CloneFlags] = &[
    CloneFlags::CLONE_NEWUSER,
    CloneFlags::CLONE_NEWPID,
    CloneFlags::CLONE_NEWUTS,
    CloneFlags::CLONE_NEWIPC,
    CloneFlags::CLONE_NEWNET,
    CloneFlags::CLONE_NEWCGROUP,
    CloneFlags::CLONE_NEWNS,
];

/// Holds information about namespaces
pub struct Namespaces {
    syscall: Box<dyn Syscall>,
    cloneFlags_linuxNameSpace: HashMap<CloneFlags, LinuxNamespace>,
}

fn linuxNameSpace2CloneFlag(namespace_type: LinuxNamespaceType) -> Result<CloneFlags> {
    let flag = match namespace_type {
        LinuxNamespaceType::User => CloneFlags::CLONE_NEWUSER,
        LinuxNamespaceType::Pid => CloneFlags::CLONE_NEWPID,
        LinuxNamespaceType::Uts => CloneFlags::CLONE_NEWUTS,
        LinuxNamespaceType::Ipc => CloneFlags::CLONE_NEWIPC,
        LinuxNamespaceType::Network => CloneFlags::CLONE_NEWNET,
        LinuxNamespaceType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
        LinuxNamespaceType::Mount => CloneFlags::CLONE_NEWNS,
        LinuxNamespaceType::Time => return Err(NamespaceError::NotSupported("time".to_string())),
    };

    Ok(flag)
}

impl TryFrom<Option<&Vec<LinuxNamespace>>> for Namespaces {
    type Error = NamespaceError;

    fn try_from(namespaces: Option<&Vec<LinuxNamespace>>) -> Result<Self> {
        let syscall: Box<dyn Syscall> = create_syscall();

        let cloneFlags_linuxNameSpace: HashMap<CloneFlags, LinuxNamespace> =
            namespaces.unwrap_or(&vec![]).iter()
                .map(|linuxNameSpace| match linuxNameSpace2CloneFlag(linuxNameSpace.typ()) {
                    Ok(flag) => Ok((flag, linuxNameSpace.clone())),
                    Err(err) => Err(err),
                }).collect::<Result<Vec<(CloneFlags, LinuxNamespace)>>>()?.into_iter().collect();

        Ok(Namespaces {
            syscall,
            cloneFlags_linuxNameSpace,
        })
    }
}

impl Namespaces {
    pub fn apply_namespaces<F: Fn(CloneFlags) -> bool>(&self, filter: F) -> Result<()> {
        let to_enter: Vec<(&CloneFlags, &LinuxNamespace)> = ORDERED_NAMESPACES
            .iter()
            .filter(|c| filter(**c))
            .filter_map(|c| self.cloneFlags_linuxNameSpace.get_key_value(c))
            .collect();

        for (_, ns) in to_enter {
            self.unshare_or_setns(ns)?;
        }
        Ok(())
    }

    pub fn unshare_or_setns(&self, namespace: &LinuxNamespace) -> Result<()> {
        tracing::debug!("unshare or setns: {:?}", namespace);
        match namespace.path() {
            Some(path) => {
                let fd = fcntl::open(path, fcntl::OFlag::empty(), stat::Mode::empty()).map_err(
                    |err| {
                        tracing::error!(?err, ?namespace, "failed to open namespace file");
                        err
                    },
                )?;

                self.syscall
                    .set_ns(fd, linuxNameSpace2CloneFlag(namespace.typ())?)
                    .map_err(|err| {
                        tracing::error!(?err, ?namespace, "failed to set namespace");
                        err
                    })?;
                unistd::close(fd).map_err(|err| {
                    tracing::error!(?err, ?namespace, "failed to close namespace file");
                    err
                })?;
            }
            None => {
                self.syscall
                    .unshare(linuxNameSpace2CloneFlag(namespace.typ())?)
                    .map_err(|err| {
                        tracing::error!(?err, ?namespace, "failed to unshare namespace");
                        err
                    })?;
            }
        }

        Ok(())
    }

    pub fn get(&self, k: LinuxNamespaceType) -> Result<Option<&LinuxNamespace>> {
        Ok(self.cloneFlags_linuxNameSpace.get(&linuxNameSpace2CloneFlag(k)?))
    }
}