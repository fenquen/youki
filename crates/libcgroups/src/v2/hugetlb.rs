use std::collections::HashMap;
use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use oci_spec::runtime::LinuxHugepageLimit;

use super::controller::Controller;
use crate::common::{
    self, read_cgroup_file, ControllerOpt, EitherError, MustBePowerOfTwo, WrappedIoError,
};
use crate::stats::{
    parse_single_value, supported_page_sizes, HugeTlbStats, StatsProvider, SupportedPageSizesError,
};

#[derive(thiserror::Error, Debug)]
pub enum V2HugeTlbControllerError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("malformed page size {page_size}: {err}")]
    MalformedPageSize {
        page_size: String,
        err: EitherError<ParseIntError, MustBePowerOfTwo>,
    },
}

pub struct HugeTlb {}

impl Controller for HugeTlb {
    type Error = V2HugeTlbControllerError;

    fn apply(
        controller_opt: &ControllerOpt,
        cgroup_root: &std::path::Path,
    ) -> Result<(), Self::Error> {
        tracing::debug!("Apply hugetlb cgroup v2 config");
        if let Some(hugepage_limits) = controller_opt.resources.hugepage_limits() {
            for hugetlb in hugepage_limits {
                Self::apply(cgroup_root, hugetlb)?
            }
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V2HugeTlbStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("getting supported huge page sizes: {0}")]
    SupportedPageSizes(#[from] SupportedPageSizesError),
    #[error("failed to parse max value for {path}: {err}")]
    ParseMax { path: PathBuf, err: ParseIntError },
}

impl StatsProvider for HugeTlb {
    type Error = V2HugeTlbStatsError;
    type Stats = HashMap<String, HugeTlbStats>;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let page_sizes = supported_page_sizes()?;
        let mut hugetlb_stats = HashMap::with_capacity(page_sizes.len());

        for page_size in page_sizes {
            hugetlb_stats.insert(
                page_size.clone(),
                Self::stats_for_page_size(cgroup_path, &page_size)?,
            );
        }

        Ok(hugetlb_stats)
    }
}

impl HugeTlb {
    fn apply(
        root_path: &Path,
        hugetlb: &LinuxHugepageLimit,
    ) -> Result<(), V2HugeTlbControllerError> {
        let page_size_raw: String = hugetlb
            .page_size()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        let page_size: u64 = match page_size_raw.parse() {
            Ok(page_size) => page_size,
            Err(err) => {
                return Err(V2HugeTlbControllerError::MalformedPageSize {
                    page_size: page_size_raw,
                    err: EitherError::Left(err),
                })
            }
        };
        if !Self::is_power_of_two(page_size) {
            return Err(V2HugeTlbControllerError::MalformedPageSize {
                page_size: page_size_raw,
                err: EitherError::Right(MustBePowerOfTwo),
            });
        }

        common::write_cgroup_file(
            root_path.join(format!("hugetlb.{}.max", hugetlb.page_size())),
            hugetlb.limit(),
        )?;

        let rsvd_file_path = root_path.join(format!("hugetlb.{}.rsvd.max", hugetlb.page_size()));
        if rsvd_file_path.exists() {
            common::write_cgroup_file(rsvd_file_path, hugetlb.limit())?;
        }

        Ok(())
    }

    fn is_power_of_two(number: u64) -> bool {
        (number != 0) && (number & (number.saturating_sub(1))) == 0
    }

    fn stats_for_page_size(
        cgroup_path: &Path,
        page_size: &str,
    ) -> Result<HugeTlbStats, V2HugeTlbStatsError> {
        let mut file_prefix = format!("hugetlb.{page_size}.rsvd");
        let mut path = cgroup_path.join(format!("{file_prefix}.events"));
        let events = read_cgroup_file(&path).or_else(|_| {
            file_prefix = format!("hugetlb.{page_size}");
            path = cgroup_path.join(format!("{file_prefix}.events"));
            read_cgroup_file(&path)
        })?;

        let fail_count: u64 = events
            .lines()
            .find(|l| l.starts_with("max"))
            .map(|l| l[3..].trim().parse())
            .transpose()
            .map_err(|err| V2HugeTlbStatsError::ParseMax {
                path: path.clone(),
                err,
            })?
            .unwrap_or_default();

        Ok(HugeTlbStats {
            usage: parse_single_value(&cgroup_path.join(format!("{file_prefix}.current")))?,
            fail_count,
            ..Default::default()
        })
    }
}