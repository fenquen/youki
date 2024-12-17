use std::fs;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use oci_spec::runtime::{Hooks, Spec};
use serde::{Deserialize, Serialize};

use crate::utils;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to save config")]
    SaveIO {
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("failed to save config")]
    SaveEncode {
        source: serde_json::Error,
        path: PathBuf,
    },
    #[error("failed to parse config")]
    LoadIO {
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("failed to parse config")]
    LoadParse {
        source: serde_json::Error,
        path: PathBuf,
    },
    #[error("missing linux in spec")]
    MissingLinux,
}

type Result<T> = std::result::Result<T, ConfigError>;

const YOUKI_CFG_FILE_NAME: &str = "youki_config.json";

/// A configuration for passing information obtained during container creation to other commands.
/// Keeping the information to a minimum improves performance.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct YoukiConfig {
    pub hooks: Option<Hooks>,
    pub cgroupPath: PathBuf,
}

impl YoukiConfig {
    pub fn from_spec(spec: &Spec, container_id: &str) -> Result<Self> {
        Ok(YoukiConfig {
            hooks: spec.hooks().clone(),
            cgroupPath: utils::get_cgroup_path(
                spec.linux().as_ref().ok_or(ConfigError::MissingLinux)?.cgroups_path(),
                container_id,
            ),
        })
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let file = fs::File::create(path.as_ref().join(YOUKI_CFG_FILE_NAME)).map_err(|err| {
            ConfigError::SaveIO {
                source: err,
                path: path.as_ref().to_owned(),
            }
        })?;

        let mut bufWriter = BufWriter::new(file);

        serde_json::to_writer(&mut bufWriter, self).map_err(|err| ConfigError::SaveEncode {
            source: err,
            path: path.as_ref().to_owned(),
        })?;

        bufWriter.flush().map_err(|err| ConfigError::SaveIO {
            source: err,
            path: path.as_ref().to_owned(),
        })?;

        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let file =
            fs::File::open(path.join(YOUKI_CFG_FILE_NAME)).map_err(|err| ConfigError::LoadIO {
                source: err,
                path: path.to_owned(),
            })?;
        let reader = BufReader::new(file);
        let config = serde_json::from_reader(reader).map_err(|err| ConfigError::LoadParse {
            source: err,
            path: path.to_owned(),
        })?;
        Ok(config)
    }
}