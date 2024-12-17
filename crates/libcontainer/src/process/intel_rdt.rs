use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nix::unistd::Pid;
use oci_spec::runtime::LinuxIntelRdt;
use once_cell::sync::Lazy;
use procfs::process::Process;
use regex::Regex;

#[derive(Debug, thiserror::Error)]
pub enum IntelRdtError {
    #[error(transparent)]
    ProcError(#[from] procfs::ProcError),
    #[error("failed to find resctrl mount point")]
    ResctrlMountPointNotFound,
    #[error("failed to find ID for resctrl")]
    ResctrlIdNotFound,
    #[error("existing schemata found but data did not match")]
    ExistingSchemataMismatch,
    #[error("failed to read existing schemata")]
    ReadSchemata(#[source] std::io::Error),
    #[error("failed to write schemata")]
    WriteSchemata(#[source] std::io::Error),
    #[error("failed to open schemata file")]
    OpenSchemata(#[source] std::io::Error),
    #[error(transparent)]
    ParseLine(#[from] ParseLineError),
    #[error("no resctrl subdirectory found for container id")]
    NoResctrlSubdirectory,
    #[error("failed to remove subdirectory")]
    RemoveSubdirectory(#[source] std::io::Error),
    #[error("no parent for resctrl subdirectory")]
    NoResctrlSubdirectoryParent,
    #[error("invalid resctrl directory")]
    InvalidResctrlDirectory,
    #[error("resctrl closID directory didn't exist")]
    NoClosIDDirectory,
    #[error("failed to write to resctrl closID directory")]
    WriteClosIDDirectory(#[source] std::io::Error),
    #[error("failed to open resctrl closID directory")]
    OpenClosIDDirectory(#[source] std::io::Error),
    #[error("failed to create resctrl closID directory")]
    CreateClosIDDirectory(#[source] std::io::Error),
    #[error("failed to canonicalize path")]
    Canonicalize(#[source] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseLineError {
    #[error("MB line doesn't match validation")]
    MBLine,
    #[error("MB token has wrong number of fields")]
    MBToken,
    #[error("L3 line doesn't match validation")]
    L3Line,
    #[error("L3 token has wrong number of fields")]
    L3Token,
}

type Result<T> = std::result::Result<T, IntelRdtError>;

pub fn delete_resctrl_subdirectory(id: &str) -> Result<()> {
    let dir = find_resctrl_mount_point().map_err(|err| {
        tracing::error!("failed to find resctrl mount point: {}", err);
        err
    })?;
    let container_resctrl_path = dir.join(id).canonicalize().map_err(|err| {
        tracing::error!(?dir, ?id, "failed to canonicalize path: {}", err);
        IntelRdtError::Canonicalize(err)
    })?;
    match container_resctrl_path.parent() {
        // Make sure the container_id really exists and the directory
        // is inside the resctrl fs.
        Some(parent) => {
            if parent == dir && container_resctrl_path.exists() {
                fs::remove_dir(&container_resctrl_path).map_err(|err| {
                    tracing::error!(path = ?container_resctrl_path, "failed to remove resctrl subdirectory: {}", err);
                    IntelRdtError::RemoveSubdirectory(err)
                })?;
            } else {
                return Err(IntelRdtError::NoResctrlSubdirectory);
            }
        }
        None => return Err(IntelRdtError::NoResctrlSubdirectoryParent),
    }
    Ok(())
}

/// Finds the resctrl mount path by looking at the process mountinfo data.
pub fn find_resctrl_mount_point() -> Result<PathBuf> {
    let process = Process::myself()?;
    let mount_infos = process.mountinfo()?;

    for mount_info in mount_infos.0.iter() {
        // "resctrl" type fs can be mounted only once.
        if mount_info.fs_type == "resctrl" {
            let path = mount_info.mount_point.clone().canonicalize().map_err(|err| {
                tracing::error!(path = ?mount_info.mount_point, "failed to canonicalize path: {}", err);
                IntelRdtError::Canonicalize(err)
            })?;
            return Ok(path);
        }
    }

    Err(IntelRdtError::ResctrlMountPointNotFound)
}

/// Adds container PID to the tasks file in the correct resctrl
/// pseudo-filesystem subdirectory.  Creates the directory if needed based on
/// the rules in Linux OCI runtime config spec.
fn write_container_pid_to_resctrl_tasks(
    path: &Path,
    id: &str,
    init_pid: Pid,
    only_clos_id_set: bool,
) -> Result<bool> {
    let tasks = path.to_owned().join(id).join("tasks");
    let dir = tasks.parent();
    match dir {
        None => Err(IntelRdtError::InvalidResctrlDirectory),
        Some(resctrl_container_dir) => {
            let mut created_dir = false;
            if !resctrl_container_dir.exists() {
                if only_clos_id_set {
                    // Directory doesn't exist and only clos_id is set: error out.
                    return Err(IntelRdtError::NoClosIDDirectory);
                }
                fs::create_dir_all(resctrl_container_dir).map_err(|err| {
                    tracing::error!("failed to create resctrl subdirectory: {}", err);
                    IntelRdtError::CreateClosIDDirectory(err)
                })?;
                created_dir = true;
            }
            // TODO(ipuustin): File doesn't need to be created, but it's easier
            // to test this way. Fix the tests so that the fake resctrl
            // filesystem is pre-populated.
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(tasks)
                .map_err(|err| {
                    tracing::error!("failed to open resctrl tasks file: {}", err);
                    IntelRdtError::OpenClosIDDirectory(err)
                })?;
            write!(file, "{init_pid}").map_err(|err| {
                tracing::error!("failed to write to resctrl tasks file: {}", err);
                IntelRdtError::WriteClosIDDirectory(err)
            })?;
            Ok(created_dir)
        }
    }
}

/// Merges the two schemas together, removing lines starting with "MB:" from
/// l3_cache_schema if mem_bw_schema is also specified.
fn combine_l3_cache_and_mem_bw_schemas(
    l3_cache_schema: &Option<String>,
    mem_bw_schema: &Option<String>,
) -> Option<String> {
    match (l3_cache_schema, mem_bw_schema) {
        (Some(ref real_l3_cache_schema), Some(ref real_mem_bw_schema)) => {
            // Combine the results. Filter out "MB:"-lines from l3_cache_schema
            let mut output: Vec<&str> = vec![];

            for line in real_l3_cache_schema.lines() {
                if line.starts_with("MB:") {
                    continue;
                }
                output.push(line);
            }
            output.push(real_mem_bw_schema);
            Some(output.join("\n"))
        }
        (Some(_), None) => {
            // Apprarently the "MB:"-lines don't need to be removed in this case?
            l3_cache_schema.to_owned()
        }
        (None, Some(_)) => mem_bw_schema.to_owned(),
        (None, None) => None,
    }
}

#[derive(PartialEq)]
enum LineType {
    L3Line,
    L3DataLine,
    L3CodeLine,
    MbLine,
    Unknown,
}

#[derive(PartialEq)]
struct ParsedLine {
    line_type: LineType,
    tokens: HashMap<String, String>,
}

/// Parse tokens ("1=7000") from a "MB:" line.
fn parse_mb_line(line: &str) -> std::result::Result<HashMap<String, String>, ParseLineError> {
    let mut token_map = HashMap::new();

    static MB_VALIDATE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^MB:(?:\s|;)*(?:\w+\s*=\s*\w+)?(?:(?:\s*;+\s*)+\w+\s*=\s*\w+)*(?:\s|;)*$")
            .unwrap()
    });
    static MB_CAPTURE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\w+)\s*=\s*(\w+)").unwrap());

    if !MB_VALIDATE_RE.is_match(line) {
        return Err(ParseLineError::MBLine);
    }

    for token in MB_CAPTURE_RE.captures_iter(line) {
        match (token.get(1), token.get(2)) {
            (Some(key), Some(value)) => {
                token_map.insert(key.as_str().to_string(), value.as_str().to_string());
            }
            _ => return Err(ParseLineError::MBToken),
        }
    }

    Ok(token_map)
}

/// Parse tokens ("0=ffff") from a L3{,CODE,DATA} line.
fn parse_l3_line(line: &str) -> std::result::Result<HashMap<String, String>, ParseLineError> {
    let mut token_map = HashMap::new();

    static L3_VALIDATE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^(?:L3|L3DATA|L3CODE):(?:\s|;)*(?:\w+\s*=\s*[[:xdigit:]]+)?(?:(?:\s*;+\s*)+\w+\s*=\s*[[:xdigit:]]+)*(?:\s|;)*$").unwrap()
    });
    static L3_CAPTURE_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(\w+)\s*=\s*0*([[:xdigit:]]+)").unwrap());
    //                                        ^
    //                          +-------------+
    //                          |
    // The capture regexp also removes leading zeros from mask values.

    if !L3_VALIDATE_RE.is_match(line) {
        return Err(ParseLineError::L3Line);
    }

    for token in L3_CAPTURE_RE.captures_iter(line) {
        match (token.get(1), token.get(2)) {
            (Some(key), Some(value)) => {
                token_map.insert(key.as_str().to_string(), value.as_str().to_string());
            }
            _ => return Err(ParseLineError::L3Token),
        }
    }

    Ok(token_map)
}

/// Get the resctrl line type. We only support L3{,CODE,DATA} and MB.
fn get_line_type(line: &str) -> LineType {
    if line.starts_with("L3:") {
        return LineType::L3Line;
    }
    if line.starts_with("L3CODE:") {
        return LineType::L3CodeLine;
    }
    if line.starts_with("L3DATA:") {
        return LineType::L3DataLine;
    }
    if line.starts_with("MB:") {
        return LineType::MbLine;
    }

    // Empty or unknown line.
    LineType::Unknown
}

/// Parse a resctrl line.
fn parse_line(line: &str) -> Option<std::result::Result<ParsedLine, ParseLineError>> {
    let line_type = get_line_type(line);

    let maybe_tokens = match line_type {
        LineType::L3Line => parse_l3_line(line).map(Some),
        LineType::L3DataLine => parse_l3_line(line).map(Some),
        LineType::L3CodeLine => parse_l3_line(line).map(Some),
        LineType::MbLine => parse_mb_line(line).map(Some),
        LineType::Unknown => Ok(None),
    };

    match maybe_tokens {
        Err(err) => Some(Err(err)),
        Ok(None) => None,
        Ok(Some(tokens)) => Some(Ok(ParsedLine { line_type, tokens })),
    }
}

/// Compare two sets of parsed lines. Do this both ways because of possible
/// duplicate lines, meaning that the vector lengths may be different.
fn compare_lines(first_lines: &[ParsedLine], second_lines: &[ParsedLine]) -> bool {
    first_lines.iter().all(|line| second_lines.contains(line))
        && second_lines.iter().all(|line| first_lines.contains(line))
}

/// Compares that two strings have the same set of lines (even if the lines are
/// in different order).
fn is_same_schema(combined_schema: &str, existing_schema: &str) -> Result<bool> {
    // Parse the strings first to lines and then to structs. Also filter
    // out lines that are non-L3{DATA,CODE} and non-MB.
    let combined = combined_schema
        .lines()
        .filter_map(parse_line)
        .collect::<std::result::Result<Vec<ParsedLine>, _>>()?;
    let existing = existing_schema
        .lines()
        .filter_map(parse_line)
        .collect::<std::result::Result<Vec<ParsedLine>, _>>()?;

    // Compare the two sets of parsed lines.
    Ok(compare_lines(&combined, &existing))
}

/// Combines the l3_cache_schema and mem_bw_schema values together with the
/// rules given in Linux OCI runtime config spec. If clos_id_was_set parameter
/// is true and the directory wasn't created, the rules say that the schemas
/// need to be compared with the existing value and an error must be generated
/// if they don't match.
fn write_resctrl_schemata(
    path: &Path,
    id: &str,
    l3_cache_schema: &Option<String>,
    mem_bw_schema: &Option<String>,
    clos_id_was_set: bool,
    created_dir: bool,
) -> Result<()> {
    let schemata = path.to_owned().join(id).join("schemata");
    let maybe_combined_schema = combine_l3_cache_and_mem_bw_schemas(l3_cache_schema, mem_bw_schema);

    if let Some(combined_schema) = maybe_combined_schema {
        if clos_id_was_set && !created_dir {
            // Compare existing schema and error out if no match.
            let data = fs::read_to_string(&schemata).map_err(IntelRdtError::ReadSchemata)?;
            if !is_same_schema(&combined_schema, &data)? {
                Err(IntelRdtError::ExistingSchemataMismatch)?;
            }
        } else {
            // Write the combined schema to the schemata file.
            // TODO(ipuustin): File doesn't need to be created, but it's easier
            // to test this way. Fix the tests so that the fake resctrl
            // filesystem is pre-populated.
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(schemata)
                .map_err(IntelRdtError::OpenSchemata)?;
            // Prevent write!() from writing the newline with a separate call.
            let schema_with_newline = combined_schema + "\n";
            write!(file, "{schema_with_newline}").map_err(IntelRdtError::WriteSchemata)?;
        }
    }

    Ok(())
}

/// Sets up Intel RDT configuration for the container process based on the
/// OCI config. The result bool tells whether or not we need to clean up
/// the created subdirectory.
pub fn setup_intel_rdt(
    maybe_container_id: Option<&str>,
    init_pid: &Pid,
    intel_rdt: &LinuxIntelRdt,
) -> Result<bool> {
    // Find mounted resctrl filesystem, error out if it can't be found.
    let path = find_resctrl_mount_point().map_err(|err| {
        tracing::error!("failed to find a mounted resctrl file system");
        err
    })?;
    let clos_id_set = intel_rdt.clos_id().is_some();
    let only_clos_id_set =
        clos_id_set && intel_rdt.l3_cache_schema().is_none() && intel_rdt.mem_bw_schema().is_none();
    let id = match (intel_rdt.clos_id(), maybe_container_id) {
        (Some(clos_id), _) => clos_id,
        (None, Some(container_id)) => container_id,
        (None, None) => Err(IntelRdtError::ResctrlIdNotFound)?,
    };

    let created_dir = write_container_pid_to_resctrl_tasks(&path, id, *init_pid, only_clos_id_set)
        .map_err(|err| {
            tracing::error!("failed to write container pid to resctrl tasks file");
            err
        })?;
    write_resctrl_schemata(
        &path,
        id,
        intel_rdt.l3_cache_schema(),
        intel_rdt.mem_bw_schema(),
        clos_id_set,
        created_dir,
    )
    .map_err(|err| {
        tracing::error!("failed to write schemata to resctrl schemata file");
        err
    })?;

    // If closID is not set and the runtime has created the sub-directory,
    // the runtime MUST remove the sub-directory when the container is deleted.
    let need_to_delete_directory = !clos_id_set && created_dir;

    Ok(need_to_delete_directory)
}
