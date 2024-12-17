use std::fs::remove_file;
use std::path::Path;

use crate::syscall::syscall::create_syscall;
use crate::syscall::Syscall;

#[derive(Debug, thiserror::Error)]
pub enum SymlinkError {
    #[error("syscall failed")]
    Syscall {
        source: crate::syscall::SyscallError,
    },
    #[error("failed symlink: {msg}")]
    Other { msg: String },
}

type Result<T> = std::result::Result<T, SymlinkError>;

pub struct Symlink {
    syscall: Box<dyn Syscall>,
}

impl Default for Symlink {
    fn default() -> Self {
        Self::new()
    }
}

impl Symlink {
    pub fn new() -> Symlink {
        Symlink::with_syscall(create_syscall())
    }

    fn with_syscall(syscall: Box<dyn Syscall>) -> Symlink {
        Symlink { syscall }
    }

    // Create symlinks for subsystems that have been comounted e.g. cpu -> cpu,cpuacct, cpuacct -> cpu,cpuacct
    #[cfg(feature = "v1")]
    pub fn setup_comount_symlinks(&self, cgroup_root: &Path, subsystem_name: &str) -> Result<()> {
        if !subsystem_name.contains(',') {
            return Ok(());
        }

        for comount in subsystem_name.split_terminator(',') {
            let link = cgroup_root.join(comount);
            self.syscall
                .symlink(Path::new(subsystem_name), &link)
                .map_err(|err| {
                    tracing::error!("failed to symlink {link:?} to {subsystem_name:?}");
                    SymlinkError::Syscall { source: err }
                })?;
        }

        Ok(())
    }

    pub fn setup_ptmx(&self, rootfs: &Path) -> Result<()> {
        let ptmx = rootfs.join("dev/ptmx");
        if let Err(e) = remove_file(&ptmx) {
            if e.kind() != ::std::io::ErrorKind::NotFound {
                return Err(SymlinkError::Other {
                    msg: "could not delete /dev/ptmx".into(),
                });
            }
        }

        self.syscall
            .symlink(Path::new("pts/ptmx"), &ptmx)
            .map_err(|err| {
                tracing::error!("failed to symlink ptmx");
                SymlinkError::Syscall { source: err }
            })?;
        Ok(())
    }

    // separating kcore symlink out from setup_default_symlinks for a better way to do the unit test,
    // since not every architecture has /proc/kcore file.
    pub fn setup_kcore_symlink(&self, rootfs: &Path) -> Result<()> {
        if Path::new("/proc/kcore").exists() {
            self.syscall
                .symlink(Path::new("/proc/kcore"), &rootfs.join("dev/kcore"))
                .map_err(|err| {
                    tracing::error!("failed to symlink kcore");
                    SymlinkError::Syscall { source: err }
                })?;
        }
        Ok(())
    }

    pub fn setup_default_symlinks(&self, rootfs: &Path) -> Result<()> {
        let defaults = [
            ("/proc/self/fd", "dev/fd"),
            ("/proc/self/fd/0", "dev/stdin"),
            ("/proc/self/fd/1", "dev/stdout"),
            ("/proc/self/fd/2", "dev/stderr"),
        ];
        for (src, dst) in defaults {
            self.syscall
                .symlink(Path::new(src), &rootfs.join(dst))
                .map_err(|err| {
                    tracing::error!("failed to symlink defaults");
                    SymlinkError::Syscall { source: err }
                })?;
        }

        Ok(())
    }
}
