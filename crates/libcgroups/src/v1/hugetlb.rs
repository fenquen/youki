use std::collections::HashMap;
use std::num::ParseIntError;
use std::path::Path;

use oci_spec::runtime::LinuxHugepageLimit;

use super::controller::Controller;
use crate::common::{
    self, read_cgroup_file, ControllerOpt, EitherError, MustBePowerOfTwo, WrappedIoError,
};
use crate::stats::{supported_page_sizes, HugeTlbStats, StatsProvider, SupportedPageSizesError};

#[derive(thiserror::Error, Debug)]
pub enum V1HugeTlbControllerError {
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
    type Error = V1HugeTlbControllerError;
    type Resource = Vec<LinuxHugepageLimit>;

    fn apply(
        controller_opt: &ControllerOpt,
        cgroup_root: &std::path::Path,
    ) -> Result<(), Self::Error> {
        tracing::debug!("Apply Hugetlb cgroup config");

        if let Some(hugepage_limits) = Self::needs_to_handle(controller_opt) {
            for hugetlb in hugepage_limits {
                Self::apply(cgroup_root, hugetlb)?
            }
        }

        Ok(())
    }

    fn needs_to_handle<'a>(controller_opt: &'a ControllerOpt) -> Option<&'a Self::Resource> {
        if let Some(hugepage_limits) = controller_opt.resources.hugepage_limits() {
            if !hugepage_limits.is_empty() {
                return controller_opt.resources.hugepage_limits().as_ref();
            }
        }

        None
    }
}

#[derive(thiserror::Error, Debug)]
pub enum V1HugeTlbStatsError {
    #[error("io error: {0}")]
    WrappedIo(#[from] WrappedIoError),
    #[error("error getting supported page sizes: {0}")]
    SupportedPageSizes(#[from] SupportedPageSizesError),
    #[error("error parsing value: {0}")]
    Parse(#[from] ParseIntError),
}

impl StatsProvider for HugeTlb {
    type Error = V1HugeTlbStatsError;
    type Stats = HashMap<String, HugeTlbStats>;

    fn stats(cgroup_path: &Path) -> Result<Self::Stats, Self::Error> {
        let page_sizes = supported_page_sizes()?;
        let mut hugetlb_stats = HashMap::with_capacity(page_sizes.len());

        for page_size in &page_sizes {
            let stats = Self::stats_for_page_size(cgroup_path, page_size)?;
            hugetlb_stats.insert(page_size.to_owned(), stats);
        }

        Ok(hugetlb_stats)
    }
}

impl HugeTlb {
    fn apply(
        root_path: &Path,
        hugetlb: &LinuxHugepageLimit,
    ) -> Result<(), V1HugeTlbControllerError> {
        let raw_page_size: String = hugetlb
            .page_size()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        let page_size: u64 = match raw_page_size.parse() {
            Ok(page_size) => page_size,
            Err(err) => {
                return Err(V1HugeTlbControllerError::MalformedPageSize {
                    page_size: raw_page_size,
                    err: EitherError::Left(err),
                })
            }
        };
        if !Self::is_power_of_two(page_size) {
            return Err(V1HugeTlbControllerError::MalformedPageSize {
                page_size: raw_page_size,
                err: EitherError::Right(MustBePowerOfTwo),
            });
        }

        common::write_cgroup_file(
            root_path.join(format!("hugetlb.{}.limit_in_bytes", hugetlb.page_size())),
            hugetlb.limit(),
        )?;

        let rsvd_file_path = root_path.join(format!(
            "hugetlb.{}.rsvd.limit_in_bytes",
            hugetlb.page_size()
        ));
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
    ) -> Result<HugeTlbStats, V1HugeTlbStatsError> {
        let mut stats = HugeTlbStats::default();
        let mut file_prefix = format!("hugetlb.{page_size}.rsvd");
        let mut usage_file = format!("{file_prefix}.usage_in_bytes");
        let usage_content = read_cgroup_file(cgroup_path.join(&usage_file)).or_else(|_| {
            file_prefix = format!("hugetlb.{page_size}");
            usage_file = format!("{file_prefix}.usage_in_bytes");
            read_cgroup_file(cgroup_path.join(&usage_file))
        })?;
        stats.usage = usage_content.trim().parse()?;

        let max_file = format!("{file_prefix}.max_usage_in_bytes");
        let max_content = common::read_cgroup_file(cgroup_path.join(max_file))?;
        stats.max_usage = max_content.trim().parse()?;

        let failcnt_file = format!("{file_prefix}.failcnt");
        let failcnt_content = common::read_cgroup_file(cgroup_path.join(failcnt_file))?;
        stats.fail_count = failcnt_content.trim().parse()?;

        Ok(stats)
    }
}
