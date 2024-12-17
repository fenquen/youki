//! Utility functionality

use std::collections::HashMap;
use std::fs::{self, DirBuilder, File};
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};

use nix::sys::stat::Mode;
use nix::sys::statfs;
use nix::unistd::{Uid, User};
use oci_spec::runtime::Spec;

use crate::error::LibcontainerError;
use crate::user_ns::UserNsCfg;

#[derive(Debug, thiserror::Error)]
pub enum PathBufExtError {
    #[error("relative path cannot be converted to the path in the container")]
    RelativePath,
    #[error("failed to strip prefix from {path:?}")]
    StripPrefix {
        path: PathBuf,
        source: std::path::StripPrefixError,
    },
    #[error("failed to canonicalize path {path:?}")]
    Canonicalize {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to get current directory")]
    CurrentDir { source: std::io::Error },
}

pub trait PathBufExt {
    fn as_relative(&self) -> Result<&Path, PathBufExtError>;
    fn join_safely<P: AsRef<Path>>(&self, p: P) -> Result<PathBuf, PathBufExtError>;
    fn canonicalize_safely(&self) -> Result<PathBuf, PathBufExtError>;
    fn normalize(&self) -> PathBuf;
}

impl PathBufExt for Path {
    fn as_relative(&self) -> Result<&Path, PathBufExtError> {
        match self.is_relative() {
            true => Err(PathBufExtError::RelativePath),
            false => Ok(self
                .strip_prefix("/")
                .map_err(|e| PathBufExtError::StripPrefix {
                    path: self.to_path_buf(),
                    source: e,
                })?),
        }
    }

    fn join_safely<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, PathBufExtError> {
        let path = path.as_ref();
        if path.is_relative() {
            return Ok(self.join(path));
        }

        let stripped = path
            .strip_prefix("/")
            .map_err(|e| PathBufExtError::StripPrefix {
                path: self.to_path_buf(),
                source: e,
            })?;
        Ok(self.join(stripped))
    }

    /// Canonicalizes existing and not existing paths
    fn canonicalize_safely(&self) -> Result<PathBuf, PathBufExtError> {
        if self.exists() {
            self.canonicalize()
                .map_err(|e| PathBufExtError::Canonicalize {
                    path: self.to_path_buf(),
                    source: e,
                })
        } else {
            if self.is_relative() {
                let p = std::env::current_dir()
                    .map_err(|e| PathBufExtError::CurrentDir { source: e })?
                    .join(self);
                return Ok(p.normalize());
            }

            Ok(self.normalize())
        }
    }

    /// Normalizes a path. In contrast to canonicalize the path does not need to exist.
    // adapted from https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61
    fn normalize(&self) -> PathBuf {
        let mut components = self.components().peekable();
        let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
            components.next();
            PathBuf::from(c.as_os_str())
        } else {
            PathBuf::new()
        };

        for component in components {
            match component {
                Component::Prefix(..) => unreachable!(),
                Component::RootDir => {
                    ret.push(component.as_os_str());
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    ret.pop();
                }
                Component::Normal(c) => {
                    ret.push(c);
                }
            }
        }
        ret
    }
}

pub fn parse_env(envs: &[String]) -> HashMap<String, String> {
    envs.iter()
        .filter_map(|e| {
            let mut split = e.split('=');

            split.next().map(|key| {
                let value = split.collect::<Vec<&str>>().join("=");
                (key.into(), value)
            })
        })
        .collect()
}

/// Get a nix::unistd::User via UID. Potential errors will be ignored.
pub fn get_unix_user(uid: Uid) -> Option<User> {
    match User::from_uid(uid) {
        Ok(x) => x,
        Err(_) => None,
    }
}

/// Get home path of a User via UID.
pub fn get_user_home(uid: u32) -> Option<PathBuf> {
    match get_unix_user(Uid::from_raw(uid)) {
        Some(user) => Some(user.dir),
        None => None,
    }
}

/// If None, it will generate a default path for cgroups.
pub fn get_cgroup_path(cgroups_path: &Option<PathBuf>, container_id: &str) -> PathBuf {
    match cgroups_path {
        Some(cpath) => cpath.clone(),
        None => PathBuf::from(format!(":youki:{container_id}")),
    }
}

pub fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(
    path: P,
    contents: C,
) -> Result<(), std::io::Error> {
    fs::write(path.as_ref(), contents).map_err(|err| {
        tracing::error!(path = ?path.as_ref(), ?err, "failed to write file");
        err
    })?;

    Ok(())
}

pub fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<(), std::io::Error> {
    fs::create_dir_all(path.as_ref()).map_err(|err| {
        tracing::error!(path = ?path.as_ref(), ?err, "failed to create directory");
        err
    })?;
    Ok(())
}

pub fn open<P: AsRef<Path>>(path: P) -> Result<File, std::io::Error> {
    File::open(path.as_ref()).map_err(|err| {
        tracing::error!(path = ?path.as_ref(), ?err, "failed to open file");
        err
    })
}

#[derive(Debug, thiserror::Error)]
pub enum MkdirWithModeError {
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("metadata doesn't match the expected attributes")]
    MetadataMismatch,
}

/// Creates the specified directory and all parent directories with the specified mode. Ensures
/// that the directory has been created with the correct mode and that the owner of the directory
/// is the owner that has been specified
/// # Example
/// ``` no_run
/// use libcontainer::utils::create_dir_all_with_mode;
/// use nix::sys::stat::Mode;
/// use std::path::Path;
///
/// let path = Path::new("/tmp/youki");
/// create_dir_all_with_mode(&path, 1000, Mode::S_IRWXU).unwrap();
/// assert!(path.exists())
/// ```
pub fn create_dir_all_with_mode<P: AsRef<Path>>(
    path: P,
    owner: u32,
    mode: Mode,
) -> Result<(), MkdirWithModeError> {
    let path = path.as_ref();
    if !path.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(mode.bits())
            .create(path)?;
    }

    let metadata = path.metadata()?;
    if metadata.is_dir()
        && metadata.st_uid() == owner
        && metadata.st_mode() & mode.bits() == mode.bits()
    {
        Ok(())
    } else {
        Err(MkdirWithModeError::MetadataMismatch)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnsureProcfsError {
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
}

// Make sure a given path is on procfs. This is to avoid the security risk that
// /proc path is mounted over. Ref: CVE-2019-16884
pub fn ensure_procfs(path: &Path) -> Result<(), EnsureProcfsError> {
    let procfs_fd = fs::File::open(path).map_err(|err| {
        tracing::error!(?err, ?path, "failed to open procfs file");
        err
    })?;
    let fstat_info = statfs::fstatfs(&procfs_fd).map_err(|err| {
        tracing::error!(?err, ?path, "failed to fstatfs the procfs");
        err
    })?;

    if fstat_info.filesystem_type() != statfs::PROC_SUPER_MAGIC {
        tracing::error!(?path, "given path is not on the procfs");
        Err(nix::Error::EINVAL)?;
    }

    Ok(())
}

pub fn isInNewUserNs() -> Result<bool, std::io::Error> {
    let uid_map_path = "/proc/self/uid_map";
    let content = fs::read_to_string(uid_map_path)?;
    Ok(!content.contains("4294967295"))
}

/// Checks if rootless mode needs to be used
pub fn needRootless() -> Result<bool, std::io::Error> {
    if !nix::unistd::geteuid().is_root() {
        return Ok(true);
    }

    isInNewUserNs()
}

/// checks if given spec is valid for current user namespace setup
pub fn validateSpecForNewUserNs(spec: &Spec) -> Result<(), LibcontainerError> {
    let needRootless = needRootless().map_err(LibcontainerError::OtherIO)?;
    let isInNewUserNs = isInNewUserNs().map_err(LibcontainerError::OtherIO)?;
    let userNsCfg = UserNsCfg::new(spec)?;

    // In case of rootless, there are 2 possible cases :
    // we have a new user ns specified in the spec
    // or the youki is launched in a new user ns (this is how podman does it)
    // So here, we check if rootless is required,
    // but we are neither in a new user ns nor a new user ns is specified in spec
    // then it is an error
    if needRootless && !isInNewUserNs && userNsCfg.is_none() {
        return Err(LibcontainerError::NoUserNamespace);
    }

    Ok(())
}
