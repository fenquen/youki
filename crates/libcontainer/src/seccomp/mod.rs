use std::num::TryFromIntError;
use std::os::unix::io;

use libseccomp::{
    ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};
use oci_spec::runtime::{
    Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompFilterFlag, LinuxSeccompOperator,
};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("failed to translate trace action due to failed to convert errno {errno} into i16")]
    TraceAction { source: TryFromIntError, errno: i32 },
    #[error("SCMP_ACT_NOTIFY cannot be used as default action")]
    NotifyAsDefaultAction,
    #[error("SCMP_ACT_NOTIFY cannot be used for the write syscall")]
    NotifyWriteSyscall,
    #[error("failed to add arch to seccomp")]
    AddArch {
        source: libseccomp::error::SeccompError,
        arch: Arch,
    },
    #[error("failed to load seccomp context")]
    LoadContext {
        source: libseccomp::error::SeccompError,
    },
    #[error("failed to get seccomp notify id")]
    GetNotifyId {
        source: libseccomp::error::SeccompError,
    },
    #[error("failed to add rule to seccomp")]
    AddRule {
        source: libseccomp::error::SeccompError,
    },
    #[error("failed to create new seccomp filter")]
    NewFilter {
        source: libseccomp::error::SeccompError,
        default: LinuxSeccompAction,
    },
    #[error("failed to set filter flag")]
    SetFilterFlag {
        source: libseccomp::error::SeccompError,
        flag: LinuxSeccompFilterFlag,
    },
    #[error("failed to set SCMP_FLTATR_CTL_NNP")]
    SetCtlNnp {
        source: libseccomp::error::SeccompError,
    },
}

type Result<T> = std::result::Result<T, SeccompError>;

fn translate_arch(arch: Arch) -> ScmpArch {
    match arch {
        Arch::ScmpArchNative => ScmpArch::Native,
        Arch::ScmpArchX86 => ScmpArch::X86,
        Arch::ScmpArchX86_64 => ScmpArch::X8664,
        Arch::ScmpArchX32 => ScmpArch::X32,
        Arch::ScmpArchArm => ScmpArch::Arm,
        Arch::ScmpArchAarch64 => ScmpArch::Aarch64,
        Arch::ScmpArchMips => ScmpArch::Mips,
        Arch::ScmpArchMips64 => ScmpArch::Mips64,
        Arch::ScmpArchMips64n32 => ScmpArch::Mips64N32,
        Arch::ScmpArchMipsel => ScmpArch::Mipsel,
        Arch::ScmpArchMipsel64 => ScmpArch::Mipsel64,
        Arch::ScmpArchMipsel64n32 => ScmpArch::Mipsel64N32,
        Arch::ScmpArchPpc => ScmpArch::Ppc,
        Arch::ScmpArchPpc64 => ScmpArch::Ppc64,
        Arch::ScmpArchPpc64le => ScmpArch::Ppc64Le,
        Arch::ScmpArchS390 => ScmpArch::S390,
        Arch::ScmpArchS390x => ScmpArch::S390X,
    }
}

fn translate_action(action: LinuxSeccompAction, errno: Option<u32>) -> Result<ScmpAction> {
    tracing::trace!(?action, ?errno, "translating action");
    let errno = errno.map(|e| e as i32).unwrap_or(libc::EPERM);
    let action = match action {
        LinuxSeccompAction::ScmpActKill => ScmpAction::KillThread,
        LinuxSeccompAction::ScmpActTrap => ScmpAction::Trap,
        LinuxSeccompAction::ScmpActErrno => ScmpAction::Errno(errno),
        LinuxSeccompAction::ScmpActTrace => ScmpAction::Trace(
            errno
                .try_into()
                .map_err(|err| SeccompError::TraceAction { source: err, errno })?,
        ),
        LinuxSeccompAction::ScmpActAllow => ScmpAction::Allow,
        LinuxSeccompAction::ScmpActKillProcess => ScmpAction::KillProcess,
        LinuxSeccompAction::ScmpActNotify => ScmpAction::Notify,
        LinuxSeccompAction::ScmpActLog => ScmpAction::Log,
    };

    tracing::trace!(?action, "translated action");
    Ok(action)
}

fn translate_op(op: LinuxSeccompOperator, datum_b: Option<u64>) -> ScmpCompareOp {
    match op {
        LinuxSeccompOperator::ScmpCmpNe => ScmpCompareOp::NotEqual,
        LinuxSeccompOperator::ScmpCmpLt => ScmpCompareOp::Less,
        LinuxSeccompOperator::ScmpCmpLe => ScmpCompareOp::LessOrEqual,
        LinuxSeccompOperator::ScmpCmpEq => ScmpCompareOp::Equal,
        LinuxSeccompOperator::ScmpCmpGe => ScmpCompareOp::GreaterEqual,
        LinuxSeccompOperator::ScmpCmpGt => ScmpCompareOp::Greater,
        LinuxSeccompOperator::ScmpCmpMaskedEq => ScmpCompareOp::MaskedEqual(datum_b.unwrap_or(0)),
    }
}

fn check_seccomp(seccomp: &LinuxSeccomp) -> Result<()> {
    // We don't support notify as default action. After the seccomp filter is
    // created with notify, the container process will have to communicate the
    // returned fd to another process. Therefore, we need the write syscall or
    // otherwise, the write syscall will be block by the seccomp filter causing
    // the container process to hang. `runc` also disallow notify as default
    // action.
    // Note: read and close syscall are also used, because if we can
    // successfully write fd to another process, the other process can choose to
    // handle read/close syscall and allow read and close to proceed as
    // expected.
    if seccomp.default_action() == LinuxSeccompAction::ScmpActNotify {
        return Err(SeccompError::NotifyAsDefaultAction);
    }

    if let Some(syscalls) = seccomp.syscalls() {
        for syscall in syscalls {
            if syscall.action() == LinuxSeccompAction::ScmpActNotify {
                for name in syscall.names() {
                    if name == "write" {
                        return Err(SeccompError::NotifyWriteSyscall);
                    }
                }
            }
        }
    }

    Ok(())
}

#[tracing::instrument(level = "trace", skip(seccomp))]
pub fn initialize_seccomp(seccomp: &LinuxSeccomp) -> Result<Option<io::RawFd>> {
    check_seccomp(seccomp)?;

    tracing::trace!(default_action = ?seccomp.default_action(), errno = ?seccomp.default_errno_ret(), "initializing seccomp");
    let default_action = translate_action(seccomp.default_action(), seccomp.default_errno_ret())?;
    let mut ctx =
        ScmpFilterContext::new_filter(default_action).map_err(|err| SeccompError::NewFilter {
            source: err,
            default: seccomp.default_action(),
        })?;

    if let Some(flags) = seccomp.flags() {
        for flag in flags {
            match flag {
                LinuxSeccompFilterFlag::SeccompFilterFlagLog => ctx.set_ctl_log(true),
                LinuxSeccompFilterFlag::SeccompFilterFlagTsync => ctx.set_ctl_tsync(true),
                LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow => ctx.set_ctl_ssb(true),
            }
            .map_err(|err| SeccompError::SetFilterFlag {
                source: err,
                flag: *flag,
            })?;
        }
    }

    if let Some(architectures) = seccomp.architectures() {
        for &arch in architectures {
            tracing::trace!(?arch, "adding architecture");
            ctx.add_arch(translate_arch(arch))
                .map_err(|err| SeccompError::AddArch { source: err, arch })?;
        }
    }

    // The SCMP_FLTATR_CTL_NNP controls if the seccomp load function will set
    // the new privilege bit automatically in prctl. Normally this is a good
    // thing, but for us we need better control. Based on the spec, if OCI
    // runtime spec doesn't set the no new privileges in Process, we should not
    // set it here.  If the seccomp load operation fails without enough
    // privilege, so be it. To prevent this automatic behavior, we unset the
    // value here.
    ctx.set_ctl_nnp(false)
        .map_err(|err| SeccompError::SetCtlNnp { source: err })?;

    if let Some(syscalls) = seccomp.syscalls() {
        for syscall in syscalls {
            let action = translate_action(syscall.action(), syscall.errno_ret())?;
            if action == default_action {
                // When the action is the same as the default action, the rule is redundant. We can
                // skip this here to avoid failing when we add the rules.
                tracing::warn!(
                    "detect a seccomp action that is the same as the default action: {:?}",
                    syscall
                );
                continue;
            }

            for name in syscall.names() {
                let sc = match ScmpSyscall::from_name(name) {
                    Ok(x) => x,
                    Err(_) => {
                        // If we failed to resolve the syscall by name, likely the kernel
                        // doeesn't support this syscall. So it is safe to skip...
                        tracing::warn!(
                            "failed to resolve syscall, likely kernel doesn't support this. {:?}",
                            name
                        );
                        continue;
                    }
                };
                match syscall.args() {
                    Some(args) => {
                        // The `seccomp_rule_add` requires us to break multiple
                        // args attaching to the same rules into multiple rules.
                        // Breaking this rule will cause `seccomp_rule_add` to
                        // return EINVAL.
                        //
                        // From the man page: when adding syscall argument
                        // comparisons to the filter it is important to remember
                        // that while it is possible to have multiple
                        // comparisons in a single rule, you can only compare
                        // each argument once in a single rule.  In other words,
                        // you can not have multiple comparisons of the 3rd
                        // syscall argument in a single rule.
                        for arg in args {
                            let cmp = ScmpArgCompare::new(
                                arg.index() as u32,
                                translate_op(arg.op(), arg.value_two()),
                                arg.value(),
                            );
                            tracing::trace!(?name, ?action, ?arg, "add seccomp conditional rule");
                            ctx.add_rule_conditional(action, sc, &[cmp])
                                .map_err(|err| {
                                    tracing::error!(
                                        "failed to add seccomp action: {:?}. Cmp: {:?} Syscall: {name}", &action, cmp,
                                    );
                                    SeccompError::AddRule {
                                        source: err,
                                    }
                                })?;
                        }
                    }
                    None => {
                        tracing::trace!(?name, ?action, "add seccomp rule");
                        ctx.add_rule(action, sc).map_err(|err| {
                            tracing::error!(
                                "failed to add seccomp rule: {:?}. Syscall: {name}",
                                &sc
                            );
                            SeccompError::AddRule { source: err }
                        })?;
                    }
                }
            }
        }
    }

    // In order to use the SECCOMP_SET_MODE_FILTER operation, either the calling
    // thread must have the CAP_SYS_ADMIN capability in its user namespace, or
    // the thread must already have the no_new_privs bit set.
    // Ref: https://man7.org/linux/man-pages/man2/seccomp.2.html
    ctx.load()
        .map_err(|err| SeccompError::LoadContext { source: err })?;

    let fd = if is_notify(seccomp) {
        Some(
            ctx.get_notify_fd()
                .map_err(|err| SeccompError::GetNotifyId { source: err })?,
        )
    } else {
        None
    };

    Ok(fd)
}

pub fn is_notify(seccomp: &LinuxSeccomp) -> bool {
    seccomp
        .syscalls()
        .iter()
        .flatten()
        .any(|syscall| syscall.action() == LinuxSeccompAction::ScmpActNotify)
}
