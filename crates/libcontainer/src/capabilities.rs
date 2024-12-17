//! Handles Management of Capabilities
use caps::{Capability as CapsCapability, *};
use oci_spec::runtime::{Capabilities, Capability as SpecCapability, LinuxCapabilities};

use crate::syscall::{Syscall, SyscallError};

/// Converts a list of capability types to capabilities has set
fn to_set(caps: &Capabilities) -> CapsHashSet {
    let mut capabilities = CapsHashSet::new();

    for c in caps {
        let cap = c.to_cap();
        capabilities.insert(cap);
    }
    capabilities
}

pub trait CapabilityExt {
    /// Convert self to caps::Capability
    fn to_cap(&self) -> caps::Capability;
    /// Convert caps::Capability to self
    fn from_cap(c: CapsCapability) -> Self;
}

impl CapabilityExt for SpecCapability {
    /// Convert oci::runtime::Capability to caps::Capability
    fn to_cap(&self) -> caps::Capability {
        match self {
            SpecCapability::AuditControl => CapsCapability::CAP_AUDIT_CONTROL,
            SpecCapability::AuditRead => CapsCapability::CAP_AUDIT_READ,
            SpecCapability::AuditWrite => CapsCapability::CAP_AUDIT_WRITE,
            SpecCapability::BlockSuspend => CapsCapability::CAP_BLOCK_SUSPEND,
            SpecCapability::Bpf => CapsCapability::CAP_BPF,
            SpecCapability::CheckpointRestore => CapsCapability::CAP_CHECKPOINT_RESTORE,
            SpecCapability::Chown => CapsCapability::CAP_CHOWN,
            SpecCapability::DacOverride => CapsCapability::CAP_DAC_OVERRIDE,
            SpecCapability::DacReadSearch => CapsCapability::CAP_DAC_READ_SEARCH,
            SpecCapability::Fowner => CapsCapability::CAP_FOWNER,
            SpecCapability::Fsetid => CapsCapability::CAP_FSETID,
            SpecCapability::IpcLock => CapsCapability::CAP_IPC_LOCK,
            SpecCapability::IpcOwner => CapsCapability::CAP_IPC_OWNER,
            SpecCapability::Kill => CapsCapability::CAP_KILL,
            SpecCapability::Lease => CapsCapability::CAP_LEASE,
            SpecCapability::LinuxImmutable => CapsCapability::CAP_LINUX_IMMUTABLE,
            SpecCapability::MacAdmin => CapsCapability::CAP_MAC_ADMIN,
            SpecCapability::MacOverride => CapsCapability::CAP_MAC_OVERRIDE,
            SpecCapability::Mknod => CapsCapability::CAP_MKNOD,
            SpecCapability::NetAdmin => CapsCapability::CAP_NET_ADMIN,
            SpecCapability::NetBindService => CapsCapability::CAP_NET_BIND_SERVICE,
            SpecCapability::NetBroadcast => CapsCapability::CAP_NET_BROADCAST,
            SpecCapability::NetRaw => CapsCapability::CAP_NET_RAW,
            SpecCapability::Perfmon => CapsCapability::CAP_PERFMON,
            SpecCapability::Setgid => CapsCapability::CAP_SETGID,
            SpecCapability::Setfcap => CapsCapability::CAP_SETFCAP,
            SpecCapability::Setpcap => CapsCapability::CAP_SETPCAP,
            SpecCapability::Setuid => CapsCapability::CAP_SETUID,
            SpecCapability::SysAdmin => CapsCapability::CAP_SYS_ADMIN,
            SpecCapability::SysBoot => CapsCapability::CAP_SYS_BOOT,
            SpecCapability::SysChroot => CapsCapability::CAP_SYS_CHROOT,
            SpecCapability::SysModule => CapsCapability::CAP_SYS_MODULE,
            SpecCapability::SysNice => CapsCapability::CAP_SYS_NICE,
            SpecCapability::SysPacct => CapsCapability::CAP_SYS_PACCT,
            SpecCapability::SysPtrace => CapsCapability::CAP_SYS_PTRACE,
            SpecCapability::SysRawio => CapsCapability::CAP_SYS_RAWIO,
            SpecCapability::SysResource => CapsCapability::CAP_SYS_RESOURCE,
            SpecCapability::SysTime => CapsCapability::CAP_SYS_TIME,
            SpecCapability::SysTtyConfig => CapsCapability::CAP_SYS_TTY_CONFIG,
            SpecCapability::Syslog => CapsCapability::CAP_SYSLOG,
            SpecCapability::WakeAlarm => CapsCapability::CAP_WAKE_ALARM,
        }
    }

    /// Convert caps::Capability to oci::runtime::Capability
    fn from_cap(c: CapsCapability) -> SpecCapability {
        match c {
            CapsCapability::CAP_AUDIT_CONTROL => SpecCapability::AuditControl,
            CapsCapability::CAP_AUDIT_READ => SpecCapability::AuditRead,
            CapsCapability::CAP_AUDIT_WRITE => SpecCapability::AuditWrite,
            CapsCapability::CAP_BLOCK_SUSPEND => SpecCapability::BlockSuspend,
            CapsCapability::CAP_BPF => SpecCapability::Bpf,
            CapsCapability::CAP_CHECKPOINT_RESTORE => SpecCapability::CheckpointRestore,
            CapsCapability::CAP_CHOWN => SpecCapability::Chown,
            CapsCapability::CAP_DAC_OVERRIDE => SpecCapability::DacOverride,
            CapsCapability::CAP_DAC_READ_SEARCH => SpecCapability::DacReadSearch,
            CapsCapability::CAP_FOWNER => SpecCapability::Fowner,
            CapsCapability::CAP_FSETID => SpecCapability::Fsetid,
            CapsCapability::CAP_IPC_LOCK => SpecCapability::IpcLock,
            CapsCapability::CAP_IPC_OWNER => SpecCapability::IpcOwner,
            CapsCapability::CAP_KILL => SpecCapability::Kill,
            CapsCapability::CAP_LEASE => SpecCapability::Lease,
            CapsCapability::CAP_LINUX_IMMUTABLE => SpecCapability::LinuxImmutable,
            CapsCapability::CAP_MAC_ADMIN => SpecCapability::MacAdmin,
            CapsCapability::CAP_MAC_OVERRIDE => SpecCapability::MacOverride,
            CapsCapability::CAP_MKNOD => SpecCapability::Mknod,
            CapsCapability::CAP_NET_ADMIN => SpecCapability::NetAdmin,
            CapsCapability::CAP_NET_BIND_SERVICE => SpecCapability::NetBindService,
            CapsCapability::CAP_NET_BROADCAST => SpecCapability::NetBroadcast,
            CapsCapability::CAP_NET_RAW => SpecCapability::NetRaw,
            CapsCapability::CAP_PERFMON => SpecCapability::Perfmon,
            CapsCapability::CAP_SETGID => SpecCapability::Setgid,
            CapsCapability::CAP_SETFCAP => SpecCapability::Setfcap,
            CapsCapability::CAP_SETPCAP => SpecCapability::Setpcap,
            CapsCapability::CAP_SETUID => SpecCapability::Setuid,
            CapsCapability::CAP_SYS_ADMIN => SpecCapability::SysAdmin,
            CapsCapability::CAP_SYS_BOOT => SpecCapability::SysBoot,
            CapsCapability::CAP_SYS_CHROOT => SpecCapability::SysChroot,
            CapsCapability::CAP_SYS_MODULE => SpecCapability::SysModule,
            CapsCapability::CAP_SYS_NICE => SpecCapability::SysNice,
            CapsCapability::CAP_SYS_PACCT => SpecCapability::SysPacct,
            CapsCapability::CAP_SYS_PTRACE => SpecCapability::SysPtrace,
            CapsCapability::CAP_SYS_RAWIO => SpecCapability::SysRawio,
            CapsCapability::CAP_SYS_RESOURCE => SpecCapability::SysResource,
            CapsCapability::CAP_SYS_TIME => SpecCapability::SysTime,
            CapsCapability::CAP_SYS_TTY_CONFIG => SpecCapability::SysTtyConfig,
            CapsCapability::CAP_SYSLOG => SpecCapability::Syslog,
            CapsCapability::CAP_WAKE_ALARM => SpecCapability::WakeAlarm,
            CapsCapability::__Nonexhaustive => unreachable!("invalid capability"),
        }
    }
}

/// reset capabilities of process calling this to effective capabilities
/// effective capability set is set of capabilities used by kernel to perform checks
/// see <https://man7.org/linux/man-pages/man7/capabilities.7.html> for more information
pub fn reset_effective<S: Syscall + ?Sized>(syscall: &S) -> Result<(), SyscallError> {
    tracing::debug!("reset all caps");
    // permitted capabilities are all the capabilities that we are allowed to acquire
    let permitted = caps::read(None, CapSet::Permitted)?;
    syscall.set_capability(CapSet::Effective, &permitted)?;
    Ok(())
}

/// Drop any extra granted capabilities, and reset to defaults which are in oci specification
pub fn drop_privileges<S: Syscall + ?Sized>(
    cs: &LinuxCapabilities,
    syscall: &S,
) -> Result<(), SyscallError> {
    tracing::debug!("dropping bounding capabilities to {:?}", cs.bounding());
    if let Some(bounding) = cs.bounding() {
        syscall.set_capability(CapSet::Bounding, &to_set(bounding))?;
    }

    if let Some(effective) = cs.effective() {
        syscall.set_capability(CapSet::Effective, &to_set(effective))?;
    }

    if let Some(permitted) = cs.permitted() {
        syscall.set_capability(CapSet::Permitted, &to_set(permitted))?;
    }

    if let Some(inheritable) = cs.inheritable() {
        syscall.set_capability(CapSet::Inheritable, &to_set(inheritable))?;
    }

    if let Some(ambient) = cs.ambient() {
        // check specifically for ambient, as those might not always be available
        if let Err(e) = syscall.set_capability(CapSet::Ambient, &to_set(ambient)) {
            tracing::error!("failed to set ambient capabilities: {}", e);
        }
    }

    Ok(())
}