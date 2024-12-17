use std::borrow::Cow;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use tracing::Level;
use tracing_subscriber::prelude::*;

const LOG_FORMAT_TEXT: &str = "text";
const LOG_FORMAT_JSON: &str = "json";
enum LogFormat {
    Text,
    Json,
}

/// If in debug mode, default level is debug to get maximum logging
#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: &str = "debug";

/// If not in debug mode, default level is error to get important logs
#[cfg(not(debug_assertions))]
const DEFAULT_LOG_LEVEL: &str = "error";

fn detect_log_format(log_format: Option<&str>) -> Result<LogFormat> {
    match log_format {
        None | Some(LOG_FORMAT_TEXT) => Ok(LogFormat::Text),
        Some(LOG_FORMAT_JSON) => Ok(LogFormat::Json),
        Some(unknown) => bail!("unknown log format: {}", unknown),
    }
}

fn detect_log_level(input: Option<String>, is_debug: bool) -> Result<Level> {
    // We keep the `debug` flag for backward compatibility, but use `log-level`
    // as the main way to set the log level due to the flexibility. If both are
    // specified, `log-level` takes precedence.
    let log_level: Cow<str> = match input {
        None if is_debug => "debug".into(),
        None => DEFAULT_LOG_LEVEL.into(),
        Some(level) => level.into(),
    };

    Ok(Level::from_str(log_level.as_ref())?)
}

#[derive(Debug, Default)]
pub struct ObservabilityConfig {
    pub log_debug_flag: bool,
    pub log_level: Option<String>,
    pub log_file: Option<PathBuf>,
    pub log_format: Option<String>,
    #[allow(dead_code)]
    pub systemd_log: bool,
}

impl From<&crate::Opts> for ObservabilityConfig {
    fn from(opts: &crate::Opts) -> Self {
        Self {
            log_debug_flag: opts.global.debug,
            log_level: opts.youki_extend.log_level.to_owned(),
            log_file: opts.global.log.to_owned(),
            log_format: opts.global.log_format.to_owned(),
            systemd_log: opts.youki_extend.systemd_log,
        }
    }
}

pub fn init<T>(config: T) -> Result<()>
where
    T: Into<ObservabilityConfig>,
{
    let config = config.into();
    let level = detect_log_level(config.log_level, config.log_debug_flag)
        .with_context(|| "failed to parse log level")?;
    let log_level_filter = tracing_subscriber::filter::LevelFilter::from(level);
    let log_format = detect_log_format(config.log_format.as_deref())
        .with_context(|| "failed to detect log format")?;

    #[cfg(debug_assertions)]
    let journald = true;
    #[cfg(not(debug_assertions))]
    let journald = config.systemd_log;

    let systemd_journald = if journald {
        match tracing_journald::layer() {
            Ok(layer) => Some(layer.with_syslog_identifier("youki".to_string())),
            Err(err) => {
                // Do not fail if we can't open syslog, just print a warning.
                // This is the case in, e.g., docker-in-docker.
                eprintln!("failed to initialize syslog logging: {:?}", err);
                None
            }
        }
    } else {
        None
    };
    let subscriber = tracing_subscriber::registry()
        .with(log_level_filter)
        .with(systemd_journald);

    // I really dislike how we have to specify individual branch for each
    // combination, but I can't find any better way to do this. The tracing
    // crate makes it hard to build a single format layer with different
    // conditions.
    match (config.log_file.as_ref(), log_format) {
        (None, LogFormat::Text) => {
            // Text to stderr
            subscriber
                .with(
                    tracing_subscriber::fmt::layer()
                        .without_time()
                        .with_writer(std::io::stderr),
                )
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to init logger: {}", e))?;
        }
        (None, LogFormat::Json) => {
            // JSON to stderr
            subscriber
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_span_list(false)
                        .with_writer(std::io::stderr),
                )
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to init logger: {}", e))?;
        }
        (Some(path), LogFormat::Text) => {
            // Log file with text format
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(path)
                .with_context(|| "failed to open log file")?;
            subscriber
                .with(tracing_subscriber::fmt::layer().with_writer(file))
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to init logger: {}", e))?;
        }
        (Some(path), LogFormat::Json) => {
            // Log file with JSON format
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(path)
                .with_context(|| "failed to open log file")?;
            subscriber
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_span_list(false)
                        .with_writer(file),
                )
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to init logger: {}", e))?;
        }
    }

    Ok(())
}
