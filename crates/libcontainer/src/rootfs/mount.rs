use std::fs::{canonicalize, create_dir_all, OpenOptions};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
#[cfg(feature = "v1")]
use std::{borrow::Cow, collections::HashMap};

use libcgroups::common::CgroupSetup::{Hybrid, Legacy, Unified};
#[cfg(feature = "v1")]
use libcgroups::common::DEFAULT_CGROUP_ROOT;
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::mount::MsFlags;
use nix::sys::stat::Mode;
use nix::NixPath;
use oci_spec::runtime::{Mount as SpecMount, MountBuilder as SpecMountBuilder};
use procfs::process::{MountInfo, MountOptFields, Process};
use safe_path;

#[cfg(feature = "v1")]
use super::symlink::Symlink;
use super::symlink::SymlinkError;
use super::utils::{parse_mount, MountOptionConfig};
use crate::syscall::syscall::create_syscall;
use crate::syscall::{linux, Syscall, SyscallError};
use crate::utils::PathBufExt;

#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("no source in mount spec")]
    NoSource,
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("syscall")]
    Syscall(#[from] crate::syscall::SyscallError),
    #[error("nix error")]
    Nix(#[from] nix::Error),
    #[error("failed to build oci spec")]
    SpecBuild(#[from] oci_spec::OciSpecError),
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
    #[error("{0}")]
    Custom(String),
    #[error("symlink")]
    Symlink(#[from] SymlinkError),
    #[error("procfs failed")]
    Procfs(#[from] procfs::ProcError),
    #[error("unknown mount option: {0}")]
    UnsupportedMountOption(String),
}

type Result<T> = std::result::Result<T, MountError>;

#[derive(Debug)]
pub struct MountOptions<'a> {
    pub root: &'a Path,
    pub label: Option<&'a str>,
    #[allow(dead_code)]
    pub cgroup_ns: bool,
}

pub struct Mount {
    syscall: Box<dyn Syscall>,
}

impl Default for Mount {
    fn default() -> Self {
        Self::new()
    }
}

impl Mount {
    pub fn new() -> Mount {
        Mount {
            syscall: create_syscall(),
        }
    }

    pub fn setup_mount(&self, mount: &SpecMount, options: &MountOptions) -> Result<()> {
        tracing::debug!("mounting {:?}", mount);
        let mut mount_option_config = parse_mount(mount)?;

        match mount.typ().as_deref() {
            Some("cgroup") => {
                let cgroup_setup = libcgroups::common::get_cgroup_setup().map_err(|err| {
                    tracing::error!("failed to determine cgroup setup: {}", err);
                    MountError::Other(err.into())
                })?;
                match cgroup_setup {
                    Legacy | Hybrid => {
                        #[cfg(not(feature = "v1"))]
                        panic!("libcontainer can't run in a Legacy or Hybrid cgroup setup without the v1 feature");
                        #[cfg(feature = "v1")]
                        self.mount_cgroup_v1(mount, options).map_err(|err| {
                            tracing::error!("failed to mount cgroup v1: {}", err);
                            err
                        })?
                    }
                    Unified => {
                        #[cfg(not(feature = "v2"))]
                        panic!("libcontainer can't run in a Unified cgroup setup without the v2 feature");
                        #[cfg(feature = "v2")]
                        self.mount_cgroup_v2(mount, options, &mount_option_config)
                            .map_err(|err| {
                                tracing::error!("failed to mount cgroup v2: {}", err);
                                err
                            })?
                    }
                }
            }
            _ => {
                if *mount.destination() == PathBuf::from("/dev") {
                    mount_option_config.flags &= !MsFlags::MS_RDONLY;
                    self.mount_into_container(
                        mount,
                        options.root,
                        &mount_option_config,
                        options.label,
                    )
                    .map_err(|err| {
                        tracing::error!("failed to mount /dev: {}", err);
                        err
                    })?;
                } else {
                    self.mount_into_container(
                        mount,
                        options.root,
                        &mount_option_config,
                        options.label,
                    )
                    .map_err(|err| {
                        tracing::error!("failed to mount {:?}: {}", mount, err);
                        err
                    })?;
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "v1")]
    fn mount_cgroup_v1(&self, cgroup_mount: &SpecMount, options: &MountOptions) -> Result<()> {
        tracing::debug!("mounting cgroup v1 filesystem");
        // create tmpfs into which the cgroup subsystems will be mounted
        let tmpfs = SpecMountBuilder::default()
            .source("tmpfs")
            .typ("tmpfs")
            .destination(cgroup_mount.destination())
            .options(
                ["noexec", "nosuid", "nodev", "mode=755"]
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<String>>(),
            )
            .build()
            .map_err(|err| {
                tracing::error!("failed to build tmpfs for cgroup: {}", err);
                err
            })?;

        self.setup_mount(&tmpfs, options).map_err(|err| {
            tracing::error!("failed to mount tmpfs for cgroup: {}", err);
            err
        })?;

        // get all cgroup mounts on the host system
        let host_mounts: Vec<PathBuf> = libcgroups::v1::util::list_subsystem_mount_points()
            .map_err(|err| {
                tracing::error!("failed to get subsystem mount points: {}", err);
                MountError::Other(err.into())
            })?
            .into_iter()
            .filter(|p| p.as_path().starts_with(DEFAULT_CGROUP_ROOT))
            .collect();
        tracing::debug!("cgroup mounts: {:?}", host_mounts);

        // get process cgroups
        let ppid = std::os::unix::process::parent_id();
        // The non-zero ppid means that the PID Namespace is not separated.
        let ppid = if ppid == 0 { std::process::id() } else { ppid };
        let root_cgroups = Process::new(ppid as i32)?.cgroups()?.0;
        let process_cgroups: HashMap<String, String> = Process::myself()?
            .cgroups()?
            .into_iter()
            .map(|c| {
                let hierarchy = c.hierarchy;
                // When youki itself is running inside a container, the cgroup path
                // will include the path of pid-1, which needs to be stripped before
                // mounting.
                let root_pathname = root_cgroups
                    .iter()
                    .find(|c| c.hierarchy == hierarchy)
                    .map(|c| c.pathname.as_ref())
                    .unwrap_or("");
                let path = c
                    .pathname
                    .strip_prefix(root_pathname)
                    .unwrap_or(&c.pathname);
                (c.controllers.join(","), path.to_owned())
            })
            .collect();
        tracing::debug!("Process cgroups: {:?}", process_cgroups);

        let cgroup_root = options
            .root
            .join_safely(cgroup_mount.destination())
            .map_err(|err| {
                tracing::error!(
                    "could not join rootfs path with cgroup mount destination: {}",
                    err
                );
                MountError::Other(err.into())
            })?;
        tracing::debug!("cgroup root: {:?}", cgroup_root);

        let symlink = Symlink::new();

        // setup cgroup mounts for container
        for host_mount in &host_mounts {
            if let Some(subsystem_name) = host_mount.file_name().and_then(|n| n.to_str()) {
                if options.cgroup_ns {
                    self.setup_namespaced_subsystem(
                        cgroup_mount,
                        options,
                        subsystem_name,
                        subsystem_name == "systemd",
                    )?;
                } else {
                    self.setup_emulated_subsystem(
                        cgroup_mount,
                        options,
                        subsystem_name,
                        subsystem_name == "systemd",
                        host_mount,
                        &process_cgroups,
                    )?;
                }

                symlink.setup_comount_symlinks(&cgroup_root, subsystem_name)?;
            } else {
                tracing::warn!("could not get subsystem name from {:?}", host_mount);
            }
        }

        Ok(())
    }

    // On some distros cgroup subsystems are comounted e.g. cpu,cpuacct or net_cls,net_prio. These systems
    // have to be comounted in the container as well as the kernel will reject trying to mount them separately.
    #[cfg(feature = "v1")]
    fn setup_namespaced_subsystem(
        &self,
        cgroup_mount: &SpecMount,
        options: &MountOptions,
        subsystem_name: &str,
        named: bool,
    ) -> Result<()> {
        tracing::debug!(
            "Mounting (namespaced) {:?} cgroup subsystem",
            subsystem_name
        );
        let subsystem_mount = SpecMountBuilder::default()
            .source("cgroup")
            .typ("cgroup")
            .destination(cgroup_mount.destination().join(subsystem_name))
            .options(
                ["noexec", "nosuid", "nodev"]
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<String>>(),
            )
            .build()
            .map_err(|err| {
                tracing::error!("failed to build {subsystem_name} mount: {err}");
                err
            })?;

        let data: Cow<str> = if named {
            format!("name={subsystem_name}").into()
        } else {
            subsystem_name.into()
        };

        let mount_options_config = MountOptionConfig {
            flags: MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            data: data.to_string(),
            rec_attr: None,
        };

        self.mount_into_container(
            &subsystem_mount,
            options.root,
            &mount_options_config,
            options.label,
        )
        .map_err(|err| {
            tracing::error!("failed to mount {subsystem_mount:?}: {err}");
            err
        })
    }

    #[cfg(feature = "v1")]
    fn setup_emulated_subsystem(
        &self,
        cgroup_mount: &SpecMount,
        options: &MountOptions,
        subsystem_name: &str,
        named: bool,
        host_mount: &Path,
        process_cgroups: &HashMap<String, String>,
    ) -> Result<()> {
        tracing::debug!("Mounting (emulated) {:?} cgroup subsystem", subsystem_name);
        let named_hierarchy: Cow<str> = if named {
            format!("name={subsystem_name}").into()
        } else {
            subsystem_name.into()
        };

        if let Some(proc_path) = process_cgroups.get(named_hierarchy.as_ref()) {
            let emulated = SpecMountBuilder::default()
                .source(
                    host_mount
                        .join_safely(proc_path.as_str())
                        .map_err(|err| {
                            tracing::error!(
                                "failed to join mount source for {subsystem_name} subsystem: {}",
                                err
                            );
                            MountError::Other(err.into())
                        })?,
                )
                .destination(
                    cgroup_mount
                        .destination()
                        .join_safely(subsystem_name)
                        .map_err(|err| {
                            tracing::error!(
                                "failed to join mount destination for {subsystem_name} subsystem: {}",
                                err
                            );
                            MountError::Other(err.into())
                        })?,
                )
                .typ("bind")
                .options(
                    ["rw", "rbind"]
                        .iter()
                        .map(|o| o.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?;
            tracing::debug!("Mounting emulated cgroup subsystem: {:?}", emulated);

            self.setup_mount(&emulated, options).map_err(|err| {
                tracing::error!("failed to mount {subsystem_name} cgroup hierarchy: {}", err);
                err
            })?;
        } else {
            tracing::warn!("Could not mount {:?} cgroup subsystem", subsystem_name);
        }

        Ok(())
    }

    #[cfg(feature = "v2")]
    fn mount_cgroup_v2(
        &self,
        cgroup_mount: &SpecMount,
        options: &MountOptions,
        mount_option_config: &MountOptionConfig,
    ) -> Result<()> {
        tracing::debug!("Mounting cgroup v2 filesystem");

        let cgroup_mount = SpecMountBuilder::default()
            .typ("cgroup2")
            .source("cgroup")
            .destination(cgroup_mount.destination())
            .options(Vec::new())
            .build()?;
        tracing::debug!("{:?}", cgroup_mount);

        if self
            .mount_into_container(
                &cgroup_mount,
                options.root,
                mount_option_config,
                options.label,
            )
            .is_err()
        {
            let host_mount = libcgroups::v2::util::get_unified_mount_point().map_err(|err| {
                tracing::error!("failed to get unified mount point: {}", err);
                MountError::Other(err.into())
            })?;

            let process_cgroup = Process::myself()
                .map_err(|err| {
                    tracing::error!("failed to get /proc/self: {}", err);
                    MountError::Other(err.into())
                })?
                .cgroups()
                .map_err(|err| {
                    tracing::error!("failed to get process cgroups: {}", err);
                    MountError::Other(err.into())
                })?
                .into_iter()
                .find(|c| c.hierarchy == 0)
                .map(|c| PathBuf::from(c.pathname))
                .ok_or_else(|| {
                    MountError::Custom("failed to find unified process cgroup".into())
                })?;
            let bind_mount = SpecMountBuilder::default()
                .typ("bind")
                .source(host_mount.join_safely(process_cgroup).map_err(|err| {
                    tracing::error!("failed to join host mount for cgroup hierarchy: {}", err);
                    MountError::Other(err.into())
                })?)
                .destination(cgroup_mount.destination())
                .options(Vec::new())
                .build()
                .map_err(|err| {
                    tracing::error!("failed to build cgroup bind mount: {}", err);
                    err
                })?;
            tracing::debug!("{:?}", bind_mount);

            let mut mount_option_config = (*mount_option_config).clone();
            mount_option_config.flags |= MsFlags::MS_BIND;
            self.mount_into_container(
                &bind_mount,
                options.root,
                &mount_option_config,
                options.label,
            )
            .map_err(|err| {
                tracing::error!("failed to bind mount cgroup hierarchy: {}", err);
                err
            })?;
        }

        Ok(())
    }

    /// Make parent mount of rootfs private if it was shared, which is required by pivot_root.
    /// It also makes sure following bind mount does not propagate in other namespaces.
    pub fn make_parent_mount_private(&self, rootfs: &Path) -> Result<Option<MountInfo>> {
        let mount_infos = Process::myself()
            .map_err(|err| {
                tracing::error!("failed to get /proc/self: {}", err);
                MountError::Other(err.into())
            })?
            .mountinfo()
            .map_err(|err| {
                tracing::error!("failed to get mount info: {}", err);
                MountError::Other(err.into())
            })?;
        let parent_mount = find_parent_mount(rootfs, mount_infos.0)?;

        // check parent mount has 'shared' propagation type
        if parent_mount
            .opt_fields
            .iter()
            .any(|field| matches!(field, MountOptFields::Shared(_)))
        {
            self.syscall.mount(
                None,
                &parent_mount.mount_point,
                None,
                MsFlags::MS_PRIVATE,
                None,
            )?;
            Ok(Some(parent_mount))
        } else {
            Ok(None)
        }
    }

    fn mount_into_container(
        &self,
        m: &SpecMount,
        rootfs: &Path,
        mount_option_config: &MountOptionConfig,
        label: Option<&str>,
    ) -> Result<()> {
        let typ = m.typ().as_deref();
        let mut d = mount_option_config.data.to_string();

        if let Some(l) = label {
            if typ != Some("proc") && typ != Some("sysfs") {
                match mount_option_config.data.is_empty() {
                    true => d = format!("context=\"{l}\""),
                    false => d = format!("{},context=\"{}\"", mount_option_config.data, l),
                }
            }
        }

        let dest_for_host = safe_path::scoped_join(rootfs, m.destination()).map_err(|err| {
            tracing::error!(
                "failed to join rootfs {:?} with mount destination {:?}: {}",
                rootfs,
                m.destination(),
                err
            );
            MountError::Other(err.into())
        })?;

        let dest = Path::new(&dest_for_host);
        let source = m.source().as_ref().ok_or(MountError::NoSource)?;
        let src = if typ == Some("bind") {
            let src = canonicalize(source).map_err(|err| {
                tracing::error!("failed to canonicalize {:?}: {}", source, err);
                err
            })?;
            let dir = if src.is_file() {
                Path::new(&dest).parent().unwrap()
            } else {
                Path::new(&dest)
            };

            create_dir_all(dir).map_err(|err| {
                tracing::error!("failed to create dir for bind mount {:?}: {}", dir, err);
                err
            })?;

            if src.is_file() && !dest.exists() {
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(dest)
                    .map_err(|err| {
                        tracing::error!("failed to create file for bind mount {:?}: {}", src, err);
                        err
                    })?;
            }

            src
        } else {
            create_dir_all(dest).map_err(|err| {
                tracing::error!("failed to create device: {:?}", dest);
                err
            })?;

            PathBuf::from(source)
        };

        if let Err(err) =
            self.syscall
                .mount(Some(&*src), dest, typ, mount_option_config.flags, Some(&*d))
        {
            if let SyscallError::Nix(errno) = err {
                if !matches!(errno, Errno::EINVAL) {
                    tracing::error!("mount of {:?} failed. {}", m.destination(), errno);
                    return Err(err.into());
                }
            }

            self.syscall
                .mount(
                    Some(&*src),
                    dest,
                    typ,
                    mount_option_config.flags,
                    Some(&mount_option_config.data),
                )
                .map_err(|err| {
                    tracing::error!("failed to mount {src:?} to {dest:?}");
                    err
                })?;
        }

        if typ == Some("bind")
            && mount_option_config.flags.intersects(
                !(MsFlags::MS_REC
                    | MsFlags::MS_REMOUNT
                    | MsFlags::MS_BIND
                    | MsFlags::MS_PRIVATE
                    | MsFlags::MS_SHARED
                    | MsFlags::MS_SLAVE),
            )
        {
            self.syscall
                .mount(
                    Some(dest),
                    dest,
                    None,
                    mount_option_config.flags | MsFlags::MS_REMOUNT,
                    None,
                )
                .map_err(|err| {
                    tracing::error!("failed to remount {:?}: {}", dest, err);
                    err
                })?;
        }

        if let Some(mount_attr) = &mount_option_config.rec_attr {
            let open_dir = Dir::open(dest, OFlag::O_DIRECTORY, Mode::empty())?;
            let dir_fd_pathbuf = PathBuf::from(format!("/proc/self/fd/{}", open_dir.as_raw_fd()));
            self.syscall.mount_setattr(
                -1,
                &dir_fd_pathbuf,
                linux::AT_RECURSIVE,
                mount_attr,
                mem::size_of::<linux::MountAttr>(),
            )?;
        }

        Ok(())
    }
}

/// Find parent mount of rootfs in given mount infos
pub fn find_parent_mount(
    rootfs: &Path,
    mount_infos: Vec<MountInfo>,
) -> std::result::Result<MountInfo, MountError> {
    // find the longest mount point
    let parent_mount_info = mount_infos
        .into_iter()
        .filter(|mi| rootfs.starts_with(&mi.mount_point))
        .max_by(|mi1, mi2| mi1.mount_point.len().cmp(&mi2.mount_point.len()))
        .ok_or_else(|| {
            MountError::Custom(format!("can't find the parent mount of {:?}", rootfs))
        })?;
    Ok(parent_mount_info)
}
