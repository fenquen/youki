use std::path::{Path, PathBuf};

use nix::fcntl::{open, OFlag};
use nix::mount::MsFlags;
use nix::sys::stat::{umask, Mode};
use nix::unistd::{close, Gid, Uid};
use oci_spec::runtime::LinuxDevice;

use super::utils::to_sflag;
use crate::syscall::syscall::create_syscall;
use crate::syscall::Syscall;
use crate::utils::PathBufExt;

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("{0:?} is not a valid device path")]
    InvalidDevicePath(std::path::PathBuf),
    #[error("failed syscall to create device")]
    Syscall(#[from] crate::syscall::SyscallError),
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
    #[error("{0}")]
    Custom(String),
}

type Result<T> = std::result::Result<T, DeviceError>;

pub struct Device {
    syscall: Box<dyn Syscall>,
}

impl Default for Device {
    fn default() -> Self {
        Self::new()
    }
}

impl Device {
    pub fn new() -> Device {
        Device {
            syscall: create_syscall(),
        }
    }

    pub fn new_with_syscall(syscall: Box<dyn Syscall>) -> Device {
        Device { syscall }
    }

    pub fn create_devices<'a, I>(&self, rootfs: &Path, devices: I, bind: bool) -> Result<()>
    where
        I: IntoIterator<Item = &'a LinuxDevice>,
    {
        let old_mode = umask(Mode::from_bits_truncate(0o000));
        devices
            .into_iter()
            .map(|dev| {
                if !dev.path().starts_with("/dev") {
                    tracing::error!(
                        "{:?} is not a valid device path starting with /dev",
                        dev.path()
                    );
                    return Err(DeviceError::InvalidDevicePath(dev.path().to_path_buf()));
                }

                if bind {
                    self.bind_dev(rootfs, dev)
                } else {
                    self.mknod_dev(rootfs, dev)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        umask(old_mode);

        Ok(())
    }

    fn bind_dev(&self, rootfs: &Path, dev: &LinuxDevice) -> Result<()> {
        let full_container_path = create_container_dev_path(rootfs, dev)?;
        tracing::debug!(
            "bind_dev with full container path {:?}",
            full_container_path
        );

        let fd = open(
            &full_container_path,
            OFlag::O_RDWR | OFlag::O_CREAT,
            Mode::from_bits_truncate(0o644),
        )
        .map_err(|err| {
            tracing::error!("failed to open bind dev {:?}: {}", full_container_path, err);
            err
        })?;
        close(fd)?;
        self.syscall
            .mount(
                Some(dev.path()),
                &full_container_path,
                Some("bind"),
                MsFlags::MS_BIND,
                None,
            )
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    path = ?full_container_path,
                    "failed to mount bind dev",
                );
                err
            })?;

        Ok(())
    }

    fn mknod_dev(&self, rootfs: &Path, dev: &LinuxDevice) -> Result<()> {
        fn makedev(major: i64, minor: i64) -> u64 {
            ((minor & 0xff)
                | ((major & 0xfff) << 8)
                | ((minor & !0xff) << 12)
                | ((major & !0xfff) << 32)) as u64
        }

        let full_container_path = create_container_dev_path(rootfs, dev)?;

        self.syscall
            .mknod(
                &full_container_path,
                to_sflag(dev.typ()),
                Mode::from_bits_truncate(dev.file_mode().unwrap_or(0)),
                makedev(dev.major(), dev.minor()),
            )
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    path = ?full_container_path,
                    major = ?dev.major(),
                    minor = ?dev.minor(),
                    "failed to mknod device"
                );

                err
            })?;
        self.syscall
            .chown(
                &full_container_path,
                dev.uid().map(Uid::from_raw),
                dev.gid().map(Gid::from_raw),
            )
            .map_err(|err| {
                tracing::error!(
                    path = ?full_container_path,
                    ?err,
                    uid = ?dev.uid(),
                    gid = ?dev.gid(),
                    "failed to chown device"
                );

                err
            })?;

        Ok(())
    }
}

fn create_container_dev_path(rootfs: &Path, dev: &LinuxDevice) -> Result<PathBuf> {
    let relative_dev_path = dev.path().as_relative().map_err(|err| {
        tracing::error!(
            "failed to convert {:?} to relative path: {}",
            dev.path(),
            err
        );
        DeviceError::Other(err.into())
    })?;
    let full_container_path = safe_path::scoped_join(rootfs, relative_dev_path).map_err(|err| {
        tracing::error!("failed to join {rootfs:?} with {:?}: {err}", dev.path());
        DeviceError::Other(err.into())
    })?;
    std::fs::create_dir_all(
        full_container_path
            .parent()
            .unwrap_or_else(|| Path::new("")),
    )
    .map_err(|err| {
        tracing::error!(
            "failed to create parent dir of {:?}: {}",
            full_container_path,
            err
        );
        DeviceError::Other(err.into())
    })?;

    Ok(full_container_path)
}