use oci_spec::runtime::*;
use rbpf::disassembler::disassemble;
use rbpf::insn_builder::{Arch as RbpfArch, *};

pub struct Program {
    prog: BpfCode,
}

#[derive(thiserror::Error, Debug)]
pub enum ProgramError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid access: {0}")]
    InvalidAccess(char),
    #[error("{0} device not supported")]
    DeviceNotSupported(&'static str),
    #[error("wildcard device type should be removed when cleaning rules")]
    WildcardDevice,
}

impl Program {
    pub fn from_rules(
        rules: &[LinuxDeviceCgroup],
        default_allow: bool,
    ) -> Result<Self, ProgramError> {
        let mut prog = Program {
            prog: BpfCode::new(),
        };
        prog.init();

        for rule in rules.iter().rev() {
            prog.add_rule(rule)?;
        }
        prog.finalize(default_allow);
        Ok(prog)
    }

    pub fn bytecodes(&self) -> &[u8] {
        self.prog.into_bytes()
    }

    fn finalize(&mut self, default_allow: bool) {
        self.prog
            .mov(Source::Imm, RbpfArch::X32)
            .set_dst(0)
            .set_imm(default_allow as i32)
            .push();

        self.prog.exit().push();
    }

    // struct bpf_cgroup_dev_ctx: https://elixir.bootlin.com/linux/v5.3.6/source/include/uapi/linux/bpf.h#L3423
    /*
    u32 access_type
    u32 major
    u32 minor
    */
    // R2 <- type (lower 16 bit of u32 access_type at R1[0])
    // R3 <- access (upper 16 bit of u32 access_type at R1[0])
    // R4 <- major (u32 major at R1[4])
    // R5 <- minor (u32 minor at R1[8])
    fn init(&mut self) {
        self.prog
            .load_x(MemSize::Word)
            .set_src(1)
            .set_off(0)
            .set_dst(2)
            .push();

        self.prog
            .bit_and(Source::Imm, RbpfArch::X32)
            .set_dst(2)
            .set_imm(0xFFFF)
            .push();

        self.prog
            .load_x(MemSize::Word)
            .set_src(1)
            .set_off(0)
            .set_dst(3)
            .push();

        self.prog
            .right_shift(Source::Imm, RbpfArch::X32)
            .set_imm(16)
            .set_dst(3)
            .push();

        self.prog
            .load_x(MemSize::Word)
            .set_src(1)
            .set_off(4)
            .set_dst(4)
            .push();

        self.prog
            .load_x(MemSize::Word)
            .set_src(1)
            .set_off(8)
            .set_dst(5)
            .push();
    }

    fn add_rule(&mut self, rule: &LinuxDeviceCgroup) -> Result<(), ProgramError> {
        let dev_type = bpf_dev_type(rule.typ().unwrap_or_default())?;
        let access = bpf_access(rule.access().clone().unwrap_or_default())?;
        let has_access = access
            != (libbpf_sys::BPF_DEVCG_ACC_READ
                | libbpf_sys::BPF_DEVCG_ACC_WRITE
                | libbpf_sys::BPF_DEVCG_ACC_MKNOD);

        let has_major = rule.major().is_some() && rule.major().unwrap() >= 0;
        let has_minor = rule.minor().is_some() && rule.minor().unwrap() >= 0;

        // count of instructions of this rule
        let mut instruction_count = 1; // execute dev_type
        if has_access {
            instruction_count += 3;
        }
        if has_major {
            instruction_count += 1;
        }
        if has_minor {
            instruction_count += 1;
        }
        instruction_count += 2;

        // if (R2 != dev_type) goto next rule
        let mut next_rule_offset = instruction_count - 1;
        self.prog
            .jump_conditional(Cond::NotEquals, Source::Imm)
            .set_dst(2)
            .set_imm(dev_type as i32)
            .set_off(next_rule_offset)
            .push();

        if has_access {
            next_rule_offset -= 3;
            // if (R3 & access != R3 /* use R1 as a temp var */) goto next rule
            self.prog
                .mov(Source::Reg, RbpfArch::X32)
                .set_dst(1)
                .set_src(3)
                .push();

            self.prog
                .bit_and(Source::Imm, RbpfArch::X32)
                .set_dst(1)
                .set_imm(access as i32)
                .push();

            self.prog
                .jump_conditional(Cond::NotEquals, Source::Reg)
                .set_dst(1)
                .set_src(3)
                .set_off(next_rule_offset)
                .push();
        }

        if has_major {
            next_rule_offset -= 1;
            // if (R4 != major) goto next rule
            self.prog
                .jump_conditional(Cond::NotEquals, Source::Imm)
                .set_dst(4)
                .set_imm(rule.major().unwrap() as i32)
                .set_off(next_rule_offset)
                .push();
        }

        if has_minor {
            next_rule_offset -= 1;
            // if (R5 != minor) goto next rule
            self.prog
                .jump_conditional(Cond::NotEquals, Source::Imm)
                .set_dst(5)
                .set_imm(rule.minor().unwrap() as i32)
                .set_off(next_rule_offset)
                .push();
        }

        // matched, return rule.allow
        self.prog
            .mov(Source::Imm, RbpfArch::X32)
            .set_dst(0)
            .set_imm(rule.allow() as i32)
            .push();
        self.prog.exit().push();

        Ok(())
    }

    pub fn dump(&self) {
        disassemble(self.prog.into_bytes());
    }

    pub fn execute(
        &self,
        typ: LinuxDeviceType,
        major: u32,
        minor: u32,
        access: String,
    ) -> Result<u64, ProgramError> {
        let mut mem = bpf_cgroup_dev_ctx(typ, major, minor, access)?;
        let vm = rbpf::EbpfVmRaw::new(Some(self.prog.into_bytes()))?;
        let result = vm.execute_program(&mut mem[..])?;
        Ok(result)
    }
}

fn bpf_dev_type(typ: LinuxDeviceType) -> Result<u32, ProgramError> {
    let dev_type: u32 = match typ {
        LinuxDeviceType::C => libbpf_sys::BPF_DEVCG_DEV_CHAR,
        LinuxDeviceType::U => return Err(ProgramError::DeviceNotSupported("unbuffered char")),
        LinuxDeviceType::B => libbpf_sys::BPF_DEVCG_DEV_BLOCK,
        LinuxDeviceType::P => return Err(ProgramError::DeviceNotSupported("pipe device")),
        LinuxDeviceType::A => return Err(ProgramError::WildcardDevice),
    };
    Ok(dev_type)
}

fn bpf_access(access: String) -> Result<u32, ProgramError> {
    let mut v = 0_u32;
    for c in access.chars() {
        let cur_access = match c {
            'r' => libbpf_sys::BPF_DEVCG_ACC_READ,
            'w' => libbpf_sys::BPF_DEVCG_ACC_WRITE,
            'm' => libbpf_sys::BPF_DEVCG_ACC_MKNOD,
            _ => return Err(ProgramError::InvalidAccess(c)),
        };
        v |= cur_access;
    }
    Ok(v)
}

fn bpf_cgroup_dev_ctx(
    typ: LinuxDeviceType,
    major: u32,
    minor: u32,
    access: String,
) -> Result<Vec<u8>, ProgramError> {
    let mut mem = Vec::with_capacity(12);

    let mut type_access = 0_u32;
    if let Ok(t) = bpf_dev_type(typ) {
        type_access = t & 0xFFFF;
    }

    type_access |= bpf_access(access)? << 16;

    mem.extend_from_slice(&type_access.to_ne_bytes());
    mem.extend_from_slice(&major.to_ne_bytes());
    mem.extend_from_slice(&minor.to_ne_bytes());

    Ok(mem)
}