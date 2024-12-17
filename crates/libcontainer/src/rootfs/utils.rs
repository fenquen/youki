use std::path::PathBuf;
use std::str::FromStr;

use nix::mount::MsFlags;
use nix::sys::stat::SFlag;
use oci_spec::runtime::{LinuxDevice, LinuxDeviceBuilder, LinuxDeviceType, Mount};

use super::mount::MountError;
use crate::syscall::linux::{self, MountRecursive};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountOptionConfig {
    /// Mount Flags.
    pub flags: MsFlags,

    /// Mount data applied to the mount.
    pub data: String,

    /// RecAttr represents mount properties to be applied recursively.
    pub rec_attr: Option<linux::MountAttr>,
}

pub fn default_devices() -> Vec<LinuxDevice> {
    vec![
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/null"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(3)
            .file_mode(0o0666u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/zero"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(5)
            .file_mode(0o0666u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/full"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(7)
            .file_mode(0o0666u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/tty"))
            .typ(LinuxDeviceType::C)
            .major(5)
            .minor(0)
            .file_mode(0o0666u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/urandom"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(9)
            .file_mode(0o0666u32)
            .build()
            .unwrap(),
        LinuxDeviceBuilder::default()
            .path(PathBuf::from("/dev/random"))
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(8)
            .file_mode(0o0666u32)
            .build()
            .unwrap(),
    ]
}

pub fn to_sflag(dev_type: LinuxDeviceType) -> SFlag {
    match dev_type {
        LinuxDeviceType::A => SFlag::S_IFBLK | SFlag::S_IFCHR | SFlag::S_IFIFO,
        LinuxDeviceType::B => SFlag::S_IFBLK,
        LinuxDeviceType::C | LinuxDeviceType::U => SFlag::S_IFCHR,
        LinuxDeviceType::P => SFlag::S_IFIFO,
    }
}

pub fn parse_mount(m: &Mount) -> std::result::Result<MountOptionConfig, MountError> {
    let mut flags = MsFlags::empty();
    let mut data = Vec::new();
    let mut mount_attr: Option<linux::MountAttr> = None;

    if let Some(options) = &m.options() {
        for option in options {
            if let Ok(mount_attr_option) = linux::MountRecursive::from_str(option.as_str()) {
                // Some options aren't corresponding to the mount flags.
                // These options need `AT_RECURSIVE` options.
                // ref: https://github.com/opencontainers/runtime-spec/blob/main/config.md#linux-mount-options
                let (is_clear, flag) = match mount_attr_option {
                    MountRecursive::Rdonly(is_clear, flag) => (is_clear, flag),
                    MountRecursive::Nosuid(is_clear, flag) => (is_clear, flag),
                    MountRecursive::Nodev(is_clear, flag) => (is_clear, flag),
                    MountRecursive::Noexec(is_clear, flag) => (is_clear, flag),
                    MountRecursive::Atime(is_clear, flag) => (is_clear, flag),
                    MountRecursive::Relatime(is_clear, flag) => (is_clear, flag),
                    MountRecursive::Noatime(is_clear, flag) => (is_clear, flag),
                    MountRecursive::StrictAtime(is_clear, flag) => (is_clear, flag),
                    MountRecursive::NoDiratime(is_clear, flag) => (is_clear, flag),
                    MountRecursive::Nosymfollow(is_clear, flag) => (is_clear, flag),
                };

                if mount_attr.is_none() {
                    mount_attr = Some(linux::MountAttr {
                        attr_set: 0,
                        attr_clr: 0,
                        propagation: 0,
                        userns_fd: 0,
                    });
                }

                if let Some(mount_attr) = &mut mount_attr {
                    if is_clear {
                        mount_attr.attr_clr |= flag;
                    } else {
                        mount_attr.attr_set |= flag;
                        if flag & linux::MOUNT_ATTR__ATIME == flag {
                            // https://man7.org/linux/man-pages/man2/mount_setattr.2.html
                            // cannot simply specify the access-time setting in attr_set, but must
                            // also include MOUNT_ATTR__ATIME in the attr_clr field.
                            mount_attr.attr_clr |= linux::MOUNT_ATTR__ATIME;
                        }
                    }
                }
                continue;
            }

            if let Some((is_clear, flag)) = match option.as_str() {
                "defaults" => Some((false, MsFlags::empty())),
                "ro" => Some((false, MsFlags::MS_RDONLY)),
                "rw" => Some((true, MsFlags::MS_RDONLY)),
                "suid" => Some((true, MsFlags::MS_NOSUID)),
                "nosuid" => Some((false, MsFlags::MS_NOSUID)),
                "dev" => Some((true, MsFlags::MS_NODEV)),
                "nodev" => Some((false, MsFlags::MS_NODEV)),
                "exec" => Some((true, MsFlags::MS_NOEXEC)),
                "noexec" => Some((false, MsFlags::MS_NOEXEC)),
                "sync" => Some((false, MsFlags::MS_SYNCHRONOUS)),
                "async" => Some((true, MsFlags::MS_SYNCHRONOUS)),
                "dirsync" => Some((false, MsFlags::MS_DIRSYNC)),
                "remount" => Some((false, MsFlags::MS_REMOUNT)),
                "mand" => Some((false, MsFlags::MS_MANDLOCK)),
                "nomand" => Some((true, MsFlags::MS_MANDLOCK)),
                "atime" => Some((true, MsFlags::MS_NOATIME)),
                "noatime" => Some((false, MsFlags::MS_NOATIME)),
                "diratime" => Some((true, MsFlags::MS_NODIRATIME)),
                "nodiratime" => Some((false, MsFlags::MS_NODIRATIME)),
                "bind" => Some((false, MsFlags::MS_BIND)),
                "rbind" => Some((false, MsFlags::MS_BIND | MsFlags::MS_REC)),
                "unbindable" => Some((false, MsFlags::MS_UNBINDABLE)),
                "runbindable" => Some((false, MsFlags::MS_UNBINDABLE | MsFlags::MS_REC)),
                "private" => Some((true, MsFlags::MS_PRIVATE)),
                "rprivate" => Some((true, MsFlags::MS_PRIVATE | MsFlags::MS_REC)),
                "shared" => Some((true, MsFlags::MS_SHARED)),
                "rshared" => Some((true, MsFlags::MS_SHARED | MsFlags::MS_REC)),
                "slave" => Some((true, MsFlags::MS_SLAVE)),
                "rslave" => Some((true, MsFlags::MS_SLAVE | MsFlags::MS_REC)),
                "relatime" => Some((true, MsFlags::MS_RELATIME)),
                "norelatime" => Some((true, MsFlags::MS_RELATIME)),
                "strictatime" => Some((true, MsFlags::MS_STRICTATIME)),
                "nostrictatime" => Some((true, MsFlags::MS_STRICTATIME)),
                unknown => {
                    if unknown == "idmap" || unknown == "ridmap" {
                        return Err(MountError::UnsupportedMountOption(unknown.to_string()));
                    }
                    None
                }
            } {
                if is_clear {
                    flags &= !flag;
                } else {
                    flags |= flag;
                }
                continue;
            }

            data.push(option.as_str());
        }
    }
    Ok(MountOptionConfig {
        flags,
        data: data.join(","),
        rec_attr: mount_attr,
    })
}
