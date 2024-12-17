#[derive(Clone)]
pub struct ProgramInfo {
    pub id: u32,
    pub fd: i32,
}

#[derive(thiserror::Error, Debug)]
pub enum BpfError {
    #[error(transparent)]
    Errno(#[from] errno::Errno),
    #[error("Failed to increase rlimit")]
    FailedToIncreaseRLimit,
}

#[cfg_attr(test, automock)]
pub mod prog {
    use std::os::unix::io::RawFd;
    use std::ptr;

    use libbpf_sys::{bpf_insn, BPF_CGROUP_DEVICE, BPF_F_ALLOW_MULTI, BPF_PROG_TYPE_CGROUP_DEVICE};
    #[cfg(not(test))]
    use libbpf_sys::{
        bpf_prog_attach, bpf_prog_detach2, bpf_prog_get_fd_by_id, bpf_prog_load, bpf_prog_query,
    };
    #[cfg(not(test))]
    use libc::setrlimit;
    use libc::{rlimit, ENOSPC, RLIMIT_MEMLOCK};

    use super::ProgramInfo;
    // TODO: consider use of #[mockall_double]
    #[cfg(test)]
    use crate::v2::devices::mocks::mock_libbpf_sys::{
        bpf_prog_attach, bpf_prog_detach2, bpf_prog_get_fd_by_id, bpf_prog_load, bpf_prog_query,
    };
    // mocks
    // TODO: consider use of #[mockall_double]
    #[cfg(test)]
    use crate::v2::devices::mocks::mock_libc::setrlimit;

    pub fn load(license: &str, insns: &[u8]) -> Result<RawFd, super::BpfError> {
        let insns_cnt = insns.len() / std::mem::size_of::<bpf_insn>();
        let insns = insns as *const _ as *const bpf_insn;
        let mut opts = libbpf_sys::bpf_prog_load_opts {
            kern_version: 0,
            log_buf: ptr::null_mut::<::std::os::raw::c_char>(),
            log_size: 0,
            ..Default::default()
        };
        #[allow(unused_unsafe)]
        let prog_fd = unsafe {
            bpf_prog_load(
                BPF_PROG_TYPE_CGROUP_DEVICE,
                ptr::null::<::std::os::raw::c_char>(),
                license as *const _ as *const ::std::os::raw::c_char,
                insns,
                insns_cnt as u64,
                &mut opts as *mut libbpf_sys::bpf_prog_load_opts,
            )
        };

        if prog_fd < 0 {
            return Err(errno::errno().into());
        }
        Ok(prog_fd)
    }

    /// Given a fd for a cgroup, collect the programs associated with it
    pub fn query(cgroup_fd: RawFd) -> Result<Vec<ProgramInfo>, super::BpfError> {
        let mut prog_ids: Vec<u32> = vec![0_u32; 64];
        let mut attach_flags = 0_u32;
        for _ in 0..10 {
            let mut prog_cnt = prog_ids.len() as u32;
            #[allow(unused_unsafe)]
            let ret = unsafe {
                // collect ids for bpf programs
                bpf_prog_query(
                    cgroup_fd,
                    BPF_CGROUP_DEVICE,
                    0,
                    &mut attach_flags,
                    &prog_ids[0] as *const u32 as *mut u32,
                    &mut prog_cnt,
                )
            };
            if ret != 0 {
                let err = errno::errno();
                if err.0 == ENOSPC {
                    assert!(prog_cnt as usize > prog_ids.len());

                    // allocate more space and try again
                    prog_ids.resize(prog_cnt as usize, 0);
                    continue;
                }

                return Err(err.into());
            }

            prog_ids.resize(prog_cnt as usize, 0);
            break;
        }

        let mut prog_fds = Vec::with_capacity(prog_ids.len());
        for prog_id in &prog_ids {
            // collect fds for programs by getting their ids
            #[allow(unused_unsafe)]
            let prog_fd = unsafe { bpf_prog_get_fd_by_id(*prog_id) };
            if prog_fd < 0 {
                tracing::debug!("bpf_prog_get_fd_by_id failed: {}", errno::errno());
                continue;
            }
            prog_fds.push(ProgramInfo {
                id: *prog_id,
                fd: prog_fd,
            });
        }
        Ok(prog_fds)
    }

    pub fn detach2(prog_fd: RawFd, cgroup_fd: RawFd) -> Result<(), super::BpfError> {
        #[allow(unused_unsafe)]
        let ret = unsafe { bpf_prog_detach2(prog_fd, cgroup_fd, BPF_CGROUP_DEVICE) };
        if ret != 0 {
            return Err(errno::errno().into());
        }
        Ok(())
    }

    pub fn attach(prog_fd: RawFd, cgroup_fd: RawFd) -> Result<(), super::BpfError> {
        #[allow(unused_unsafe)]
        let ret =
            unsafe { bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_DEVICE, BPF_F_ALLOW_MULTI) };

        if ret != 0 {
            return Err(errno::errno().into());
        }
        Ok(())
    }

    pub fn bump_memlock_rlimit() -> Result<(), super::BpfError> {
        let rlimit = rlimit {
            rlim_cur: 128 << 20,
            rlim_max: 128 << 20,
        };

        #[allow(unused_unsafe)]
        if unsafe { setrlimit(RLIMIT_MEMLOCK, &rlimit) } != 0 {
            return Err(super::BpfError::FailedToIncreaseRLimit);
        }

        Ok(())
    }
}
