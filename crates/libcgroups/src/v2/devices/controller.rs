use std::os::unix::io::AsRawFd;
use std::path::Path;

#[cfg(test)]
use bpf::mock_prog as bpf_prog;
#[cfg(not(test))]
use bpf::prog as bpf_prog;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use oci_spec::runtime::LinuxDeviceCgroup;

use super::bpf::BpfError;
use super::program::ProgramError;
use super::*;
use crate::common::{default_allow_devices, default_devices, ControllerOpt};
use crate::v2::controller::Controller;

const LICENSE: &str = "Apache";

pub struct Devices {}

#[derive(thiserror::Error, Debug)]
pub enum DevicesControllerError {
    #[error("bpf error: {0}")]
    Bpf(#[from] BpfError),
    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),
    #[error("program error: {0}")]
    Program(#[from] ProgramError),
}

impl Controller for Devices {
    type Error = DevicesControllerError;

    fn apply(
        controller_opt: &ControllerOpt,
        cgroup_root: &Path,
    ) -> Result<(), DevicesControllerError> {
        #[cfg(not(feature = "cgroupsv2_devices"))]
        return Ok(());

        #[cfg(feature = "cgroupsv2_devices")]
        return Self::apply_devices(cgroup_root, controller_opt.resources.devices());
    }
}

impl Devices {
    pub fn apply_devices(
        cgroup_root: &Path,
        linux_devices: &Option<Vec<LinuxDeviceCgroup>>,
    ) -> Result<(), DevicesControllerError> {
        tracing::debug!("Apply Devices cgroup config");

        // FIXME: should we start as "deny all"?
        let mut emulator = emulator::Emulator::with_default_allow(false);

        // FIXME: apply user-defined and default rules in which order?
        if let Some(devices) = linux_devices {
            for d in devices {
                tracing::debug!("apply user defined rule: {:?}", d);
                emulator.add_rule(d);
            }
        }

        for d in [
            default_devices().iter().map(|d| d.into()).collect(),
            default_allow_devices(),
        ]
        .concat()
        {
            tracing::debug!("apply default rule: {:?}", d);
            emulator.add_rule(&d);
        }

        let prog = program::Program::from_rules(&emulator.rules, emulator.default_allow)?;

        // Increase `ulimit -l` limit to avoid BPF_PROG_LOAD error (#2167).
        // This limit is not inherited into the container.
        bpf_prog::bump_memlock_rlimit()?;
        let prog_fd = bpf_prog::load(LICENSE, prog.bytecodes())?;

        // FIXME: simple way to attach BPF program
        //  1. get list of existing attached programs
        //  2. attach this program (not use BPF_F_REPLACE, see below)
        //  3. detach all programs of 1
        //
        // runc will use BPF_F_REPLACE to replace currently attached program if:
        //   1. BPF_F_REPLACE is supported by kernel
        //   2. there is exactly one attached program
        // https://github.com/opencontainers/runc/blob/8e6871a3b14bb74e0ef358aca3b9f8f9cb80f041/libcontainer/cgroups/ebpf/ebpf_linux.go#L165
        //
        // IMHO, this is too complicated, and in most cases, we just attach program once without
        // already attached programs.

        // get the fd of the cgroup root
        let fd = nix::dir::Dir::open(
            cgroup_root.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            Mode::from_bits(0o600).unwrap(),
        )?;

        // collect the programs attached to this cgroup
        let old_progs = bpf_prog::query(fd.as_raw_fd())?;
        // attach our new program
        bpf_prog::attach(prog_fd, fd.as_raw_fd())?;
        // detach all previous programs
        for old_prog in old_progs {
            bpf_prog::detach2(old_prog.fd, fd.as_raw_fd())?;
        }

        Ok(())
    }
}