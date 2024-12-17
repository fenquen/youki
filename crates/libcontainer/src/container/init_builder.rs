use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use oci_spec::runtime::Spec;
use user_ns::UserNsCfg;

use super::builder::ContainerBuilder;
use super::builder_impl::ContainerBuilderImpl;
use super::{Container, ContainerStatus};
use crate::config::YoukiConfig;
use crate::error::{ErrInvalidSpec, LibcontainerError, MissingSpecError};
use crate::notify_socket::NOTIFY_SOCK_FILE_NAME;
use crate::process::args::ContainerType;
use crate::{apparmor, tty, user_ns, utils};

// Builder that can be used to configure the properties of a new container
pub struct InitContainerBuilder {
    containerBuilder: ContainerBuilder,
    bundlePath: PathBuf,
    use_systemd: bool,
    detached: bool,
}

impl InitContainerBuilder {
    /// Generates the base configuration for a new container from which
    /// configuration methods can be chained
    pub(super) fn new(containerBuilder: ContainerBuilder, bundlePath: PathBuf) -> Self {
        Self {
            containerBuilder,
            bundlePath,
            use_systemd: true,
            detached: true,
        }
    }

    /// Sets if systemd should be used for managing cgroups
    pub fn with_systemd(mut self, should_use: bool) -> Self {
        self.use_systemd = should_use;
        self
    }

    pub fn with_detach(mut self, detached: bool) -> Self {
        self.detached = detached;
        self
    }

    /// Creates a new container
    pub fn build(self) -> Result<Container, LibcontainerError> {
        let spec = self.loadSpecFromFile()?;

        // rootPath/containerId
        let containerRootPath = self.createContainerRoot()?;

        let mut container = self.createContainer(&containerRootPath)?;
        container.set_systemd(self.use_systemd).set_annotations(spec.annotations().clone());

        let notifySockFilePath = containerRootPath.join(NOTIFY_SOCK_FILE_NAME);

        // convert path of root file system of the container to absolute path
        let rootfsPath = fs::canonicalize(spec.root().as_ref().ok_or(MissingSpecError::Root)?.path()).map_err(LibcontainerError::OtherIO)?;

        // if socket file path is given in commandline options,get file descriptors of console socket
        let consoleSockFd =
            if let Some(console_socket) = &self.containerBuilder.console_socket {
                Some(tty::setup_console_socket(&containerRootPath, console_socket, "console-socket")?)
            } else {
                None
            };

        let userNsCfg = UserNsCfg::new(&spec)?;

        let youkiCfg = YoukiConfig::from_spec(&spec, container.id())?;
        youkiCfg.save(&containerRootPath).map_err(|err| {
            tracing::error!(?containerRootPath, "failed to save config: {}", err);
            err
        })?;

        let mut containerBuilderImpl = ContainerBuilderImpl {
            container_type: ContainerType::InitContainer,
            syscall: self.containerBuilder.syscall,
            container_id: self.containerBuilder.container_id,
            pid_file: self.containerBuilder.pid_file,
            console_socket: consoleSockFd,
            use_systemd: self.use_systemd,
            spec: Rc::new(spec),
            rootfs: rootfsPath,
            user_ns_config: userNsCfg,
            notify_path: notifySockFilePath,
            container: Some(container.clone()),
            preserve_fds: self.containerBuilder.preserve_fds,
            detached: self.detached,
            executor: self.containerBuilder.executor,
        };

        containerBuilderImpl.create()?;

        container.refresh_state()?;

        Ok(container)
    }

    fn createContainerRoot(&self) -> Result<PathBuf, LibcontainerError> {
        let containerRootPath = self.containerBuilder.rootPath.join(&self.containerBuilder.container_id);
        tracing::debug!("container directory will be {:?}", containerRootPath);

        if containerRootPath.exists() {
            tracing::error!(id = self.containerBuilder.container_id, dir = ?containerRootPath, "container already exists");
            return Err(LibcontainerError::Exist);
        }

        fs::create_dir_all(&containerRootPath).map_err(|err| {
            tracing::error!(?containerRootPath,"failed to create container directory: {}",err);
            LibcontainerError::OtherIO(err)
        })?;

        Ok(containerRootPath)
    }

    /// 读取bundlePath的config.json
    fn loadSpecFromFile(&self) -> Result<Spec, LibcontainerError> {
        let specFilePath = self.bundlePath.join("config.json");

        let mut spec = Spec::load(specFilePath)?;
        Self::validateSpec(&spec)?;

        spec.canonicalize_rootfs(&self.bundlePath).map_err(|err| {
            tracing::error!(bundle = ?self.bundlePath, "failed to canonicalize rootfs: {}", err);
            err
        })?;

        Ok(spec)
    }

    fn validateSpec(spec: &Spec) -> Result<(), LibcontainerError> {
        let version = spec.version();
        if !version.starts_with("1.") {
            tracing::error!("runtime spec has incompatible version '{}'. Only 1.X.Y is supported",spec.version());
            Err(ErrInvalidSpec::UnsupportedVersion)?;
        }

        if let Some(process) = spec.process() {
            if let Some(profile) = process.apparmor_profile() {
                let apparmor_is_enabled = apparmor::is_enabled().map_err(|err| {
                    tracing::error!(?err, "failed to check if apparmor is enabled");
                    LibcontainerError::OtherIO(err)
                })?;

                if !apparmor_is_enabled {
                    tracing::error!(?profile, "apparmor profile exists in the spec, but apparmor is not activated on this system");
                    Err(ErrInvalidSpec::AppArmorNotEnabled)?;
                }
            }

            if let Some(io_priority) = process.io_priority() {
                let priority = io_priority.priority();
                let iop_class_res = serde_json::to_string(&io_priority.class());
                match iop_class_res {
                    Ok(iop_class) => {
                        if !(0..=7).contains(&priority) {
                            tracing::error!(?priority, "io priority '{}' not between 0 and 7 (inclusive), class '{}' not in (IO_PRIO_CLASS_RT,IO_PRIO_CLASS_BE,IO_PRIO_CLASS_IDLE)",priority, iop_class);
                            Err(ErrInvalidSpec::IoPriority)?;
                        }
                    }
                    Err(e) => {
                        tracing::error!(?priority, ?e, "failed to parse io priority class");
                        Err(ErrInvalidSpec::IoPriority)?;
                    }
                }
            }
        }

        utils::validateSpecForNewUserNs(spec)?;

        Ok(())
    }

    fn createContainer(&self, containerRootPath: &Path) -> Result<Container, LibcontainerError> {
        let container = Container::new(
            &self.containerBuilder.container_id,
            ContainerStatus::Creating,
            None,
            &self.bundlePath,
            containerRootPath,
        )?;
        container.saveState2File()?;
        Ok(container)
    }
}
