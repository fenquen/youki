use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use nix::unistd::Pid;
use procfs::process::Process;

use crate::config::YoukiConfig;
use crate::container::{ContainerStatus, State};
use crate::error::LibcontainerError;
use crate::syscall::syscall::create_syscall;

#[derive(Debug, Clone)]
pub struct Container {
    pub state: State,

    /// rootPath/containerName
    pub rootPath: PathBuf,
}

impl Default for Container {
    fn default() -> Self {
        Self {
            state: State::default(),
            rootPath: PathBuf::from("/run/youki"),
        }
    }
}

impl Container {
    pub fn new(containerId: &str,
               containerStatus: ContainerStatus,
               pid: Option<i32>,
               bundlePath: &Path,
               containerRootPath: &Path) -> Result<Self, LibcontainerError> {
        let containerRootPath = fs::canonicalize(containerRootPath).map_err(|err| {
            LibcontainerError::InvalidInput(format!("invalid container root {containerRootPath:?}: {err:?}"))
        })?;

        let bundlePath = fs::canonicalize(bundlePath).map_err(|err| {
            LibcontainerError::InvalidInput(format!("invalid bundle {bundlePath:?}: {err:?}"))
        })?;

        let state = State::new(containerId, containerStatus, pid, bundlePath);

        Ok(Self {
            state,
            rootPath: containerRootPath,
        })
    }

    pub fn id(&self) -> &str {
        &self.state.id
    }

    pub fn can_start(&self) -> bool {
        self.state.status.can_start()
    }

    pub fn can_kill(&self) -> bool {
        self.state.status.can_kill()
    }

    pub fn can_delete(&self) -> bool {
        self.state.status.can_delete()
    }

    pub fn can_exec(&self) -> bool {
        self.state.status == ContainerStatus::Running
    }

    pub fn can_pause(&self) -> bool {
        self.state.status.can_pause()
    }

    pub fn can_resume(&self) -> bool {
        self.state.status.can_resume()
    }

    pub fn bundle(&self) -> &PathBuf {
        &self.state.bundle
    }

    pub fn set_annotations(&mut self, annotations: Option<HashMap<String, String>>) -> &mut Self {
        self.state.annotations = annotations;
        self
    }

    pub fn pid(&self) -> Option<Pid> {
        self.state.pid.map(Pid::from_raw)
    }

    pub fn set_pid(&mut self, pid: i32) -> &mut Self {
        self.state.pid = Some(pid);
        self
    }

    pub fn created(&self) -> Option<DateTime<Utc>> {
        self.state.created
    }

    pub fn creator(&self) -> Option<OsString> {
        if let Some(uid) = self.state.creator {
            let command = create_syscall();
            let user_name = command.get_pwuid(uid);
            if let Some(user_name) = user_name {
                return Some((*user_name).to_owned());
            }
        }

        None
    }

    pub fn set_creator(&mut self, uid: u32) -> &mut Self {
        self.state.creator = Some(uid);
        self
    }

    pub fn systemd(&self) -> bool {
        self.state.use_systemd
    }

    pub fn set_systemd(&mut self, should_use: bool) -> &mut Self {
        self.state.use_systemd = should_use;
        self
    }

    pub fn set_clean_up_intel_rdt_directory(&mut self, clean_up: bool) -> &mut Self {
        self.state.clean_up_intel_rdt_subdirectory = Some(clean_up);
        self
    }

    pub fn clean_up_intel_rdt_subdirectory(&self) -> Option<bool> {
        self.state.clean_up_intel_rdt_subdirectory
    }

    pub fn status(&self) -> ContainerStatus {
        self.state.status
    }

    pub fn set_status(&mut self, status: ContainerStatus) -> &mut Self {
        let created = match (status, self.state.created) {
            (ContainerStatus::Created, None) => Some(Utc::now()),
            _ => self.state.created,
        };

        self.state.created = created;
        self.state.status = status;

        self
    }

    pub fn refresh_status(&mut self) -> Result<(), LibcontainerError> {
        let new_status = match self.pid() {
            Some(pid) => {
                // Note that Process::new does not spawn a new process
                // but instead creates a new Process structure, and fill
                // it with information about the process with given pid
                if let Ok(proc) = Process::new(pid.as_raw()) {
                    use procfs::process::ProcState;

                    match proc.stat()?.state()? {
                        ProcState::Zombie | ProcState::Dead => ContainerStatus::Stopped,
                        _ => match self.status() {
                            ContainerStatus::Creating
                            | ContainerStatus::Created
                            | ContainerStatus::Paused => self.status(),
                            _ => ContainerStatus::Running,
                        },
                    }
                } else {
                    ContainerStatus::Stopped
                }
            }
            None => ContainerStatus::Stopped,
        };

        self.set_status(new_status);
        Ok(())
    }

    pub fn refresh_state(&mut self) -> Result<&mut Self, LibcontainerError> {
        let state = State::load(&self.rootPath)?;
        self.state = state;

        Ok(self)
    }

    pub fn load(container_root: PathBuf) -> Result<Self, LibcontainerError> {
        let state = State::load(&container_root)?;
        let mut container = Self {
            state,
            rootPath: container_root,
        };
        container.refresh_status()?;
        Ok(container)
    }

    pub fn saveState2File(&self) -> Result<(), LibcontainerError> {
        tracing::debug!("Save container status: {:?} in {:?}", self, self.rootPath);
        self.state.save(&self.rootPath)?;

        Ok(())
    }

    pub fn spec(&self) -> Result<YoukiConfig, LibcontainerError> {
        let spec = YoukiConfig::load(&self.rootPath)?;
        Ok(spec)
    }
}

/// Checkpoint parameter structure
pub struct CheckpointOptions {
    pub ext_unix_sk: bool,
    pub file_locks: bool,
    pub image_path: PathBuf,
    pub leave_running: bool,
    pub shell_job: bool,
    pub tcp_established: bool,
    pub work_path: Option<PathBuf>,
}