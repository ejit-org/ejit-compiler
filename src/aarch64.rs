use crate::{
    CallInfo, CompilerResult, Cond, CpuInfo, CpuLevel, EntryInfo, Error, Executable, Fixup, Compiler, Ins, PcRel4, RegClass, RegInfo, Scale, Src, State, Type, Vsize, R
};

pub mod regs {
    use crate::R;

    pub const X0: R = R(0);
    pub const X1: R = R(1);
    pub const X2: R = R(2);
    pub const X3: R = R(3);
    pub const X4: R = R(4);
    pub const X5: R = R(5);
    pub const X6: R = R(6);
    pub const X7: R = R(7);
    pub const X8: R = R(8);
    pub const X9: R = R(9);
    pub const X10: R = R(10);
    pub const X11: R = R(11);
    pub const X12: R = R(12);
    pub const X13: R = R(13);
    pub const X14: R = R(14);
    pub const X15: R = R(15);
    pub const X16: R = R(16);
    pub const X17: R = R(17);
    pub const X18: R = R(18);
    pub const X19: R = R(19);
    pub const X20: R = R(20);
    pub const X21: R = R(21);
    pub const X22: R = R(22);
    pub const X23: R = R(23);
    pub const X24: R = R(24);
    pub const X25: R = R(25);
    pub const X26: R = R(26);
    pub const X27: R = R(27);
    pub const X28: R = R(28);

    pub const TMP: R = X8;
    pub const FP: R = R(29);
    pub const LR: R = R(30);
    pub const SP: R = R(31);
    pub const XZR: R = R(31);

    pub const V0: R = R(32 + 0);
    pub const V1: R = R(32 + 1);
    pub const V2: R = R(32 + 2);
    pub const V3: R = R(32 + 3);
    pub const V4: R = R(32 + 4);
    pub const V5: R = R(32 + 5);
    pub const V6: R = R(32 + 6);
    pub const V7: R = R(32 + 7);
    pub const V8: R = R(32 + 8);
    pub const V9: R = R(32 + 9);
    pub const V10: R = R(32 + 10);
    pub const V11: R = R(32 + 11);
    pub const V12: R = R(32 + 12);
    pub const V13: R = R(32 + 13);
    pub const V14: R = R(32 + 14);
    pub const V15: R = R(32 + 15);
    pub const V16: R = R(32 + 16);
    pub const V17: R = R(32 + 17);
    pub const V18: R = R(32 + 18);
    pub const V19: R = R(32 + 19);
    pub const V20: R = R(32 + 20);
    pub const V21: R = R(32 + 21);
    pub const V22: R = R(32 + 22);
    pub const V23: R = R(32 + 23);
    pub const V24: R = R(32 + 24);
    pub const V25: R = R(32 + 25);
    pub const V26: R = R(32 + 26);
    pub const V27: R = R(32 + 27);
    pub const V28: R = R(32 + 28);
    pub const V29: R = R(32 + 29);
    pub const V30: R = R(32 + 30);
    pub const V31: R = R(32 + 31);
}

// See https://github.com/ARM-software/abi-aa/blob/main/sysvabi64/sysvabi64.rst
// https://en.wikipedia.org/wiki/Calling_convention
const REG_INFO : &[RegInfo] = &[
    // x0-x7
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: Some(0), ret: Some(0), name: "x0" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: Some(1), ret: Some(1), name: "x1" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: Some(2), ret: Some(2), name: "x2" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: Some(3), ret: Some(3), name: "x3" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: Some(4), ret: Some(4), name: "x4" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: Some(5), ret: Some(5), name: "x5" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: Some(6), ret: Some(6), name: "x6" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: Some(7), ret: Some(7), name: "x7" },
    // x8-x15
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: true, arg: None, ret: None, name: "x8" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "x9" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "x10" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "x11" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "x12" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "x13" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "x14" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "x15" },
    // x16-x23
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: None, ret: None, name: "x16" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: false, arg: None, ret: None, name: "x17" },
    RegInfo { reg_class: RegClass::GPR, callee_save: false, scratch: false, special: true, arg: None, ret: None, name: "x18" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x19" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x20" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x21" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x22" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x23" },
    // x24-x31
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x24" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x25" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x26" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x27" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "x28" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: false, special: false, arg: None, ret: None, name: "x29" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: false, special: true, arg: None, ret: None, name: "x30" },
    RegInfo { reg_class: RegClass::GPR, callee_save: true, scratch: false, special: true, arg: None, ret: None, name: "x31" },

    // v0-v7
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: false, special: false, arg: Some(0), ret: Some(0), name: "v0" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: false, special: false, arg: Some(1), ret: Some(1), name: "v1" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: false, special: false, arg: Some(2), ret: Some(2), name: "v2" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: false, special: false, arg: Some(3), ret: Some(3), name: "v3" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: false, special: false, arg: Some(4), ret: Some(4), name: "v4" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: false, special: false, arg: Some(5), ret: Some(5), name: "v5" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: false, special: false, arg: Some(6), ret: Some(6), name: "v6" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: false, special: false, arg: Some(7), ret: Some(7), name: "v7" },
    // v8-v15
    RegInfo { reg_class: RegClass::VREG, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "v8" },
    RegInfo { reg_class: RegClass::VREG, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "v9" },
    RegInfo { reg_class: RegClass::VREG, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "v10" },
    RegInfo { reg_class: RegClass::VREG, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "v11" },
    RegInfo { reg_class: RegClass::VREG, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "v12" },
    RegInfo { reg_class: RegClass::VREG, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "v13" },
    RegInfo { reg_class: RegClass::VREG, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "v14" },
    RegInfo { reg_class: RegClass::VREG, callee_save: true, scratch: true, special: false, arg: None, ret: None, name: "v15" },
    // v16-v23
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v16" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v17" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v18" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v19" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v20" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v21" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v22" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v23" },
    // v24-v31
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v24" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v25" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v26" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v27" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v28" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v29" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v30" },
    RegInfo { reg_class: RegClass::VREG, callee_save: false, scratch: true, special: false, arg: None, ret: None, name: "v31" },
];

pub fn native_compiler(cpu_info: CpuInfo) -> Aarch64Compiler {
    Aarch64Compiler::new(cpu_info)
}

pub fn native_cpu_info() -> CpuInfo {
    cpu_info(CpuLevel::Simd128)
}

/// 
pub fn cpu_info(cpu_level: CpuLevel) -> CpuInfo {
    // let compiler = Aarch64Compiler::new(&CpuInfo::default());

    // pre-allocate SP
    let alloc0 = 1 << SP.0;
    // Note for avx512, we will have 32 vector registers.
    // let max_regs = [16, 16];

    // See https://github.com/ARM-software/abi-aa/blob/main/sysvabi64/sysvabi64.rst
    // https://en.wikipedia.org/wiki/Calling_convention

    // X0-X7 Arguments and return values
    // X8 Indirect result
    // X9-X15 Temporary
    // X16-X17 Intra-procedure-call temporary
    // X18 Platform defined use
    // X19-X28 Temporary (must be preserved)
    // X29 Frame pointer (must be preserved)
    // X30 Return address
    // SP Stack pointer
    // XZR Zero
    // PC Program counter

    // TODO: build this all from REG_INFO
    use regs::*;
    CpuInfo {
        cpu_level,
        reg_info: &REG_INFO,
        alloc: [alloc0, 0],
        args: Box::from(&[X0, X1, X2, X3, X4, X5, X6, X7][..]),
        res: Box::from(&[X0, X1, X2, X3, X4, X5, X6, X7][..]),
        any: Box::from(
            &[
                X0, X1, X2, X3, X4, X5, X6, X7, X9, X10, X11, X12, X13, X14, X15, X16, X17, X19,
                X20, X21, X22, X23, X24, X25, X26, X27, X28,
            ][..],
        ),
        // TODO: Check
        save: Box::from(&[X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, FP][..]),
        // TODO: Check
        scratch: Box::from(&[X9, X10, X11, X12, X13, X14, X15][..]),
        sp: SP,
        // TODO: update this.
        vargs: Box::from(&[V0, V1, V2, V3, V4, V5, V6, V7][..]),
        vres: Box::from(&[V0, V1, V2, V3, V4, V5, V6, V7][..]),
        vsave: Box::from(&[][..]),
        vscratch: (0..7).map(|i| R(V0.0 + i)).collect(),
        vany: (0..=28).map(|i| R(V0.0 + i)).collect(),
    }
}

type Optype = u32;
const OP_ADDS: Optype = 0xab000000;
const OP_ADDI: u32 = 0xb1000000;
const OP_SUBS: Optype = 0xeb000000;
const OP_SUBI: u32 = 0xf1000000;
const OP_ADCS: Optype = 0xba000000;
const OP_SBCS: Optype = 0xfa000000;
const OP_ANDS: Optype = 0xea000000;
const OP_ORR: Optype = 0xaa000000;
const OP_EOR: Optype = 0xca000000;
const OP_MUL: Optype = 0x9b007c00;
const OP_UDIV: Optype = 0x9ac00800;
const OP_SDIV: Optype = 0x9ac00c00;
const OP_LSL: Optype = 0x9ac02000;
const OP_LSR: Optype = 0x9ac02400;
const OP_ASR: Optype = 0x9ac02800;

const OP_MOV: Optype = 0xaa0003e0;
const OP_MVN: Optype = 0xaa2003e0;
const OP_NEG: Optype = 0xcb0003e0;
const OP_CMP: Optype = 0xeb00001f;

const OP_ADR: u32 = 0x10000000;

const OP_BR: Optype = 0xd61f0000;
const OP_BLR: Optype = 0xd63f0000;
const OP_BCC: Optype = 0x54000000;
const OP_B: Optype = 0x14000000;

impl Cond {
    fn to_arm64(&self) -> u32 {
        match self {
            Cond::Eq => 0x00,
            Cond::Ne => 0x01,
            Cond::Sgt => 0x0c,
            Cond::Sge => 0x0a,
            Cond::Slt => 0x0b,
            Cond::Sle => 0x0d,
            Cond::Ugt => 0x08,
            Cond::Uge => 0x02,
            Cond::Ult => 0x03,
            Cond::Ule => 0x09,
        }
    }
}

pub struct Aarch64Compiler {
    state: State,
}

impl Aarch64Compiler {
    pub fn new(cpu_info: CpuInfo) -> Self {
        Aarch64Compiler {
            state: State::new(cpu_info),
        }
    }
}

impl Compiler for Aarch64Compiler {
    fn state(&mut self) -> &mut State {
        &mut self.state
    }

    fn addr(&mut self, reg: R, value: u32, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn ld(&mut self, ty: Type, reg1: R, reg2: R, offset: i32, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn st(&mut self, ty: Type, reg1: R, reg2: R, offset: i32, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vld(&mut self, ty: Type, vsize: Vsize, reg1: R, reg2: R, offset: i32, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vst(&mut self, ty: Type, vsize: Vsize, reg1: R, reg2: R, offset: i32, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn add(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        let state = self.state();
        check_args(dest, src1, src2, i, state)?;
        if let Some(src2) = src2.as_gpr(&state.cpu_info) {
            let (rd, rn, rm) = (dest.to_arm64(), src1.to_arm64(), src2.to_arm64());
            gen::reg_shifted(state, OP_ADDS, 0, rm, 0, rn, rd)?;
        } else if let Some(imm) = src2.as_imm64() {
            let (rd, rn) = (dest.to_arm64(), src1.to_arm64());
            if imm & !0xfff == 0 {
                gen::imm_shifted( state, OP_ADDI, 0, imm as u32, rn, rd)?;
            } else if imm & !(0xfff << 12) == 0 {
                gen::imm_shifted(state, OP_ADDI, 1, (imm >> 12) as u32, rn, rd)?;
            } else {
                gen::ld_constant(state, regs::TMP.to_arm64(), imm)?;
                gen::reg_shifted(state, OP_ADDS, 0, regs::TMP.to_arm64(), 0, rn, rd)?;
            }
        } else {
            return Err(Error::InvalidSrcArgument(i.clone()));
        }
        Ok(())
    }

    fn sub(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        let state = self.state();
        check_args(dest, src1, src2, i, state)?;
        if let Some(src2) = src2.as_gpr(&state.cpu_info) {
            let (rd, rn, rm) = (dest.to_arm64(), src1.to_arm64(), src2.to_arm64());
            gen::reg_shifted(state, OP_SUBS, 0, rm, 0, rn, rd)?;
        } else if let Some(imm) = src2.as_imm64() {
            let (rd, rn) = (dest.to_arm64(), src1.to_arm64());
            if imm & !0xfff == 0 {
                gen::imm_shifted( state, OP_SUBI, 0, imm as u32, rn, rd)?;
            } else if imm & !(0xfff << 12) == 0 {
                gen::imm_shifted(state, OP_SUBI, 1, (imm >> 12) as u32, rn, rd)?;
            } else {
                gen::ld_constant(state, regs::TMP.to_arm64(), imm)?;
                gen::reg_shifted(state, OP_SUBS, 0, regs::TMP.to_arm64(), 0, rn, rd)?;
            }
        } else {
            return Err(Error::InvalidSrcArgument(i.clone()));
        }
        Ok(())
    }

    fn adc(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn sbb(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn and(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn or(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn xor(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn shl(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn shr(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn sar(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn mul(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn udiv(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn sdiv(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn mov(&mut self, dest: R, src: &Src, i: &Ins) -> Result<(), Error> {
        let state = self.state();
        if dest.rc(&state.cpu_info) != RegClass::GPR {
            return Err(Error::BadRegClass(i.clone()));
        }
        if let Some(r) = src.as_gpr(&state.cpu_info) {
            if r != dest {
                gen_unary(state, OP_MOV, dest, src, i);
            }
        } else if let Some(imm) = src.as_imm64() {
            gen::ld_constant(state, dest.to_arm64(), imm);
        } else {
            return Err(Error::InvalidSrcArgument(i.clone()));
        }
        Ok(())
    }

    fn cmp(&mut self, reg: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn not(&mut self, reg: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn neg(&mut self, reg: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn push(&mut self, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn pop(&mut self, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vadd(&mut self, ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vsub(&mut self, ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vand(&mut self, ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vor(&mut self, ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vxor(&mut self, ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vshl(&mut self, ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vshr(&mut self, ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vmul(&mut self, ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vmov(&mut self, ty: Type, vsize: Vsize, reg: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vrecpe(&mut self, ty: Type, vsize: Vsize, reg: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vrsqrte(&mut self, ty: Type, vsize: Vsize, reg: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn call(&mut self, call_info: &CallInfo, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn call_local(&mut self, value: u32, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn ci(&mut self, reg: R, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn bi(&mut self, reg: R, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn br(&mut self, cond: Cond, value: u32, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn jmp(&mut self, value: u32, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn cmov(&mut self, cond: Cond, reg: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn ret(&mut self, i: &Ins) -> Result<(), Error> {
        todo!()
    }
}

fn check_args(dest: R, src1: R, src2: &Src, i: &Ins, state: &mut State) -> Result<(), Error> {
    if dest.rc(&state.cpu_info) != RegClass::GPR || src1.rc(&state.cpu_info) != RegClass::GPR {
        return Err(Error::BadRegClass(i.clone()));
    }
    if let Some(src2) = src2.as_gpr(&state.cpu_info) {
        if src2 == regs::SP {
            return Err(Error::SpNotAllowed(i.clone()));
        }
    }
    Ok(())
}

fn gen_store(state: &mut State, ty: Type, r: R, ra: R, imm: i32, i: &Ins) -> Result<(), Error> {
    // use Type::*;
    // let op = match ty {
    //     U8 | S8 => (OP_STB, false, 0),
    //     U16 | S16 => (OP_STW, true, 0),
    //     U32 | S32 => (OP_STD, false, 0),
    //     U64 | S64 => (OP_STQ, false, 1),
    //     _ => return Err(Error::InvalidType(i.clone())),
    // };
    // gen_load_store(state, op, pfx_66, w, &r, &ra, imm, i)?;
    Ok(())
}

fn gen_load(state: &mut State, ty: Type, r: R, ra: R, imm: i32, i: &Ins) -> Result<(), Error> {
    // use Type::*;
    // let (op, pfx_66, w) = match ty {
    //     U8 => (OP_LDZB, false, 1),
    //     U16 => (OP_LDZW, true, 1),
    //     U32 => (OP_LDZD, false, 0),
    //     U64 => (OP_LDZQ, false, 1),
    //     S8 => (OP_LDSB, false, 1),
    //     S16 => (OP_LDSW, true, 1),
    //     S32 => (OP_LDSD, false, 1),
    //     S64 => (OP_LDSQ, false, 1),
    //     _ => return Err(Error::InvalidType(i.clone())),
    // };
    // gen_load_store(state, op, pfx_66, w, &r, &ra, imm, i)?;
    Ok(())
}


/// Generate a call including register assignments and saves.
fn gen_call(state: &mut State, call_info: &CallInfo, i: &Ins) -> Result<(), Error> {
    // for src in call_info.saves.iter() {
    //     gen_push(state, src, i)?;
    // }

    // let mut num_iargs = 0;
    // let mut num_vargs = 0;
    // let mut bytes_pushed = 0;
    // let mut movs = Vec::new();
    // for arg in &call_info.args {
    //     if arg.is_reg() || arg.is_imm64() {
    //         if let Some(dest) = state.cpu_info.args.get(num_iargs).cloned() {
    //             movs.push((dest, arg.clone()));
    //             // gen_mov(state, &dest, &arg, i)?;
    //             num_iargs += 1;
    //         } else {
    //             gen_push(state, &arg, i)?;
    //             bytes_pushed += 8;
    //         }
    //     } else {
    //         // TODO: vector/fp args
    //         return Err(Error::InvalidSrcArgument(i.clone()));
    //     }
    // }

    // // The parameter moves may break if an earlier dest is a later src.
    // // Example:
    // //    mov  rdi, rbx
    // //    mov  rsi, rdi
    // // Here we need to re-order.
    // // Note: we will be in a pickle if there is a cycle, in which case we need to use an exchange.
    // for i in 0..movs.len() {
    //     let (dest, src) = movs[i].clone();
    //     if movs[1..]
    //         .iter()
    //         .find(|(dest2, src2)| src2.as_gpr() == Some(dest))
    //         .is_some()
    //     {
    //         movs.push((dest.clone(), src.clone()));
    //         // Noop mov.
    //         movs[i] = (dest, dest.into());
    //     }
    // }

    // for (dest, src) in movs {
    //     gen_mov(state, &dest, &src, i)?;
    // }

    // let pos = state.constant(&call_info.ptr.to_le_bytes());
    // state.code.extend([0xff, 0x15]); // ff 15 00 00 00 00       call   *0x0(%rip)
    // let loc = state.code.len();
    // state.code.extend(0_i32.to_le_bytes());
    // state.fixups.push((loc, Fixup::Const(pos, 4)));

    // if bytes_pushed != 0 {
    //     gen_binary(
    //         state,
    //         OP_ADD,
    //         &regs::RSP,
    //         &regs::RSP,
    //         &bytes_pushed.into(),
    //         i,
    //     )?;
    // }

    // for src in call_info.saves.iter().rev() {
    //     gen_pop(state, src, i)?;
    // }
    Ok(())
}

/// Vector immediate instructions use constants.
fn gen_vimm(
    state: &mut State,
    opcodes: &[(u8, u8); 6],
    ty: Type,
    vsize: Vsize,
    v: &R,
    imm: i64,
    i: &Ins,
) -> Result<(), Error> {
    // if ty.bits() > vsize.bits() || ty.bits() > 64 {
    //     return Err(Error::InvalidType(i.clone()));
    // }
    // if vsize.bits() > 256 {
    //     // state.cpu_level.max_vbits()
    //     // TODO: support avx512
    //     return Err(Error::InvalidType(i.clone()));
    // }
    // let elems = vsize.bits() / ty.bits();
    // let mut c = vec![0_u8; vsize.bits() / 8];
    // let esize = ty.bits() / 8;
    // for e in 0..elems {
    //     c[e * esize..(e + 1) * esize].copy_from_slice(&imm.to_le_bytes()[0..esize]);
    // }
    // let pos = state.constant(&c);

    // // PC relative load
    // let (p, op) = match ty {
    //     Type::U8 | Type::S8 => opcodes[0],
    //     Type::U16 | Type::S16 => opcodes[1],
    //     Type::U32 | Type::S32 => opcodes[2],
    //     Type::U64 | Type::S64 => opcodes[3],
    //     Type::F32 => opcodes[4],
    //     Type::F64 => opcodes[5],
    //     _ => return Err(Error::UnsupportedVectorOperation(i.clone())),
    // };
    // let (r, x, b, w) = (v.to_x86_high(), 0, 0, 0);
    // let modrm = 0x00 + 5 + v.to_x86_low() * 0x08;
    // let l = if vsize == Vsize::V128 { 0 } else { 1 };
    // gen_vex(state, r, x, b, w, 1, 0, l, p, op, modrm);
    // let loc = state.code.len();
    // state.code.extend(0_i32.to_le_bytes());
    // state.fixups.push((loc, Fixup::Const(pos, 4)));
    Ok(())
}

fn gen_vop(
    state: &mut State,
    opcodes: &[(u8, u8); 6],
    ty: &Type,
    vsize: Vsize,
    v: &R,
    v1: &R,
    v2: &Src,
    i: &Ins,
) -> Result<(), Error> {
    // https://www.felixcloutier.com/x86/paddb:paddw:paddd:paddq
    // https://www.felixcloutier.com/x86/addps
    // https://en.wikipedia.org/wiki/X86_SIMD_instruction_listings

    // if vsize.bits() > 256 {
    //     // state.cpu_level.max_vbits()
    //     // TODO: support avx512
    //     return Err(Error::InvalidType(i.clone()));
    // }

    // if let Some(v2) = v2.as_gpr() {
    //     let modrm = 0xc0 + v2.to_x86_low() + v.to_x86_low() * 8;
    //     let (r, x, b, w) = (v.to_x86_high(), 0, v2.to_x86_high(), 0);
    //     let l = if vsize == Vsize::V128 { 0 } else { 1 };
    //     let v = v1.to_x86();
    //     let m = 1; // 0x0f
    //                // See OP_VADD etc.
    //     let (p, op) = match ty {
    //         Type::U8 | Type::S8 => opcodes[0],
    //         Type::U16 | Type::S16 => opcodes[1],
    //         Type::U32 | Type::S32 => opcodes[2],
    //         Type::U64 | Type::S64 => opcodes[3],
    //         Type::F32 => opcodes[4],
    //         Type::F64 => opcodes[5],
    //         _ => return Err(Error::UnsupportedVectorOperation(i.clone())),
    //     };
    //     if op == 0x00 {
    //         return Err(Error::UnsupportedVectorOperation(i.clone()));
    //     }
    //     gen_vex(state, r, x, b, w, 1, v, l, p, op, modrm);
    // } else if let Some(imm) = v2.as_imm64() {
    //     gen_vimm(state, opcodes, *ty, vsize, v, imm, i)?;
    // } else {
    //     return Err(Error::InvalidSrcArgument(i.clone()));
    // }

    Ok(())
}

fn gen_addr(
    state: &mut State,
    r: u8,
    base: Option<&R>,
    index: Option<&R>,
    scale: Scale,
    imm: i32,
    i: &Ins,
) -> Result<(), Error> {
    // if index == Some(&regs::RSP) {
    //     return Err(Error::InvalidAddress(i.clone()));
    // }
    // let base_low = base.map(|r| r.to_x86_low()).unwrap_or_default();
    // let modrm_mod = if imm == 0 && base_low != 5 {
    //     0
    // } else if TryInto::<i8>::try_into(imm).is_ok() {
    //     1
    // } else {
    //     2
    // };
    // if base_low != 4 && scale == Scale::X1 && index.is_none() {
    //     state.code.push(modrm_mod * 0x40 + r * 0x08 + base_low);
    // } else {
    //     let index = index.map(R::to_x86_low).unwrap_or(4);
    //     state.code.extend([
    //         modrm_mod * 0x40 + r * 0x08 + 4,
    //         scale.to_sib() * 0x40 + index * 0x08 + base_low,
    //     ]);
    // }
    // if modrm_mod == 1 {
    //     state
    //         .code
    //         .extend(&TryInto::<i8>::try_into(imm).unwrap().to_le_bytes());
    // } else if modrm_mod == 2 {
    //     state.code.extend(imm.to_le_bytes());
    // }
    Ok(())
}

/// deprecate this.
fn gen_load_store(
    state: &mut State,
    opcode: &[u8],
    pfx_66: bool,
    w: u8,
    r: &R,
    ra: &R,
    imm: i32,
    i: &Ins,
) -> Result<(), Error> {
    // let has_pfx = opcode[1] == 0x0f;
    // let op = if has_pfx { opcode[2] } else { opcode[1] };
    // if pfx_66 {
    //     state.code.push(OP_PFX_66);
    // }
    // state
    //     .code
    //     .push(rex(r.to_x86_high(), 0, ra.to_x86_high(), w));
    // if has_pfx {
    //     state.code.push(0x0f);
    // }
    // state.code.push(op);
    // gen_addr(state, r.to_x86_low(), Some(ra), None, Scale::X1, imm, &i)
    Ok(())
}

fn gen_vload_store(
    state: &mut State,
    vsize: Vsize,
    op: u8,
    v: &R,
    ra: &R,
    imm: i32,
    i: &Ins,
) -> Result<(), Error> {
    // let (r, x, b, w) = (v.to_x86_high(), 0, ra.to_x86_high(), 0);
    // let modrm = 0x80 + ra.to_x86_low() + v.to_x86_low() * 0x08;
    // let l = if vsize == Vsize::V128 { 0 } else { 1 };
    // gen_vex(state, r, x, b, w, 1, 0, l, 0, op, modrm);
    // state.code.extend(imm.to_le_bytes());
    Ok(())
}

impl R {
    // VEX bits.
    pub fn to_arm64(&self) -> u32 {
        self.0 as u32
    }
}

fn gen_binary(
    state: &mut State,
    op: Optype,
    dest: &R,
    src1: &R,
    src2: &Src,
    i: &Ins,
) -> Result<(), Error> {
    if dest.rc(&state.cpu_info) != RegClass::GPR || src1.rc(&state.cpu_info) != RegClass::GPR {
        return Err(Error::BadRegClass(i.clone()));
    }
    if let Some(src2) = src2.as_gpr(&state.cpu_info) {
        if src2 == regs::SP {
            return Err(Error::SpNotAllowed(i.clone()));
        }
        gen::reg_shifted(
            state,
            op,
            0,
            src2.to_arm64(),
            0,
            src1.to_arm64(),
            dest.to_arm64(),
        )?;
    } else if let Some(imm) = src2.as_imm64() {
        match op {
            OP_ADDS if imm & !0xfff == 0 => {
                gen::imm_shifted(
                    state,
                    0xb1000000,
                    0,
                    imm as u32,
                    src1.to_arm64(),
                    dest.to_arm64(),
                )?;
            }
            OP_ADDS if imm & !(0xfff << 12) == 0 => {
                gen::imm_shifted(
                    state,
                    0xb1000000,
                    1,
                    (imm >> 12) as u32,
                    src1.to_arm64(),
                    dest.to_arm64(),
                )?;
            }
            OP_SUBS if imm & !0xfff == 0 => {
                gen::imm_shifted(
                    state,
                    0xf1000000,
                    0,
                    imm as u32,
                    src1.to_arm64(),
                    dest.to_arm64(),
                )?;
            }
            OP_SUBS if imm & !(0xfff << 12) == 0 => {
                gen::imm_shifted(
                    state,
                    0xf1000000,
                    1,
                    (imm >> 12) as u32,
                    src1.to_arm64(),
                    dest.to_arm64(),
                )?;
            }
            _ => {
                if imm == 0 {
                    gen::reg_shifted(
                        state,
                        op,
                        0,
                        regs::XZR.to_arm64(),
                        0,
                        src1.to_arm64(),
                        dest.to_arm64(),
                    )?;
                } else {
                    // TODO: use get_bitconst_opcode for and, or etc.
                    gen::ld_constant(state, regs::TMP.to_arm64(), imm)?;
                    gen::reg_shifted(
                        state,
                        op,
                        0,
                        regs::TMP.to_arm64(),
                        0,
                        src1.to_arm64(),
                        dest.to_arm64(),
                    )?;
                }
            }
        }
    } else {
        return Err(Error::InvalidSrcArgument(i.clone()));
    }
    Ok(())
}

fn gen_unary(state: &mut State, op: u32, dest: R, src: &Src, i: &Ins) -> Result<(), Error> {
    if let Some(src) = src.as_gpr(&state.cpu_info) {
        if op == OP_CMP {
            gen::reg_shifted(
                state,
                op,
                0,
                src.to_arm64(),
                0,
                dest.to_arm64(),
                regs::XZR.to_arm64(),
            )?;
        } else {
            gen::reg_shifted(
                state,
                op,
                0,
                src.to_arm64(),
                0,
                regs::XZR.to_arm64(),
                dest.to_arm64(),
            )?;
        }
    } else if let Some(imm) = src.as_imm64() {
        match op {
            OP_NEG => {
                gen::ld_constant(state, dest.to_arm64(), imm.wrapping_neg())?;
            }
            OP_MVN => {
                gen::ld_constant(state, dest.to_arm64(), !imm)?;
            }
            OP_CMP => {
                gen::ld_constant(state, regs::TMP.to_arm64(), imm)?;
                gen_unary(state, op, dest, &regs::TMP.into(), i);
            }
            OP_MOV => {
                gen::ld_constant(state, dest.to_arm64(), imm)?;
            }
            _ => unreachable!(),
        }
    } else {
        return Err(Error::InvalidSrcArgument(i.clone()));
    }
    Ok(())
}

// fn gen_mov(state: &mut State, dest: &R, src: &Src, i: &Ins) -> Result<(), Error> {
//     if dest.rc(&state.cpu_info) != RegClass::GPR {
//         return Err(Error::BadRegClass(i.clone()));
//     }
//     if let Some(r) = src.as_gpr(&state.cpu_info) {
//         if &r != dest {
//             gen_unary(state, OP_MOV, dest, src, i);
//         }
//     } else if let Some(imm) = src.as_imm64() {
//         gen::ld_constant(state, dest.to_arm64(), imm);
//     } else {
//         return Err(Error::InvalidSrcArgument(i.clone()));
//     }
//     Ok(())
// }

/// The push instruction on x86 is quite efficient and is great
/// fo constant generation.
fn gen_push(state: &mut State, src: &Src, i: &Ins) -> Result<(), Error> {
    match src {
        Src::SR(r) => {
            let r = R(*r);
            if r == state.cpu_info.sp() {
                return Err(Error::InvalidSrcArgument(i.clone()));
            }
            match r.rc(&state.cpu_info) {
                RegClass::GPR => {
                    todo!();
                }
                RegClass::VREG => {
                    todo!();
                }
                _ => return Err(Error::InvalidSrcArgument(i.clone())),
            }
        }
        Src::Imm(imm) => {
            let imm = *imm;
            gen::ld_constant(state, regs::TMP.to_arm64(), imm);
            todo!()
        }
        Src::Bytes(items) => {
            todo!()
        }
    }
    Ok(())
}

fn gen_pop(state: &mut State, dest: &Src, i: &Ins) -> Result<(), Error> {
    // if let Some(dest) = dest.as_gpr() {
    //     if dest.rc(&state.cpu_info) != RegClass::GPR {
    //         return Err(Error::BadRegClass(i.clone()));
    //     }
    //     let op = OP_POP + dest.to_x86_low();
    //     if dest.to_x86_high() == 0 {
    //         state.code.extend([op]);
    //     } else {
    //         let rex = 0x40 + dest.to_x86_high();
    //         state.code.extend([rex, op]);
    //     }
    // } else {
    //     return Err(Error::InvalidArgs);
    // }
    Ok(())
}

pub mod gen {
    use crate::{Cond, Error, Fixup, PcRel4, State, R};

    use super::{OP_ADR, OP_BCC};

    // Reserved	0	op0	0	0	0	0	op1
    // SME	1	op0	0	0	0	0	Varies
    pub fn sme(state: &mut State) -> Result<(), Error> {
        Ok(())
    }

    // Unallocated		0	0	0	1

    // SVE		0	0	1	0	Varies
    pub fn sve(state: &mut State) -> Result<(), Error> {
        Ok(())
    }

    // Unallocated		0	0	1	1

    // Data Processing — Immediate PC-rel.	op	immlo	1	0	0	0	0	immhi	Rd
    pub fn pc_rel(state: &mut State) -> Result<(), Error> {
        Ok(())
    }

    // Data Processing — Immediate Others	sf		1	0	0	01–11		Rd
    pub fn imm_shifted(
        state: &mut State,
        op: u32,
        shift: u32,
        imm: u32,
        rn: u32,
        rd: u32,
    ) -> Result<(), Error> {
        let opcode = op | shift << 22 | imm << 10 | rn << 5 | rd;
        state.code.extend(opcode.to_le_bytes());
        Ok(())
    }

    // Branches + System Instructions	op0	1	0	1	op1		op2
    pub(crate) fn branch_indirect(state: &mut State, op: u32, reg: u32) {
        state.code.extend((op | reg << 5).to_le_bytes());
    }

    pub(crate) fn branch_cond(state: &mut State, cond: u32, label: u32) {
        let fixup = Fixup::PcRel4(PcRel4 {
            label,
            offset: 0,
            bits: 19,
            rshift: 2,
            lshift: 5,
            delta: 0,
        });
        state.fixups.push((state.code.len(), fixup));
        state.code.extend((OP_BCC | cond).to_le_bytes());
    }

    pub fn branch(state: &mut State, op: u32, label: u32) {
        let fixup = Fixup::PcRel4(PcRel4 {
            label,
            offset: 0,
            bits: 26,
            rshift: 2,
            lshift: 0,
            delta: 0,
        });
        state.fixups.push((state.code.len(), fixup));
        state.code.extend(op.to_le_bytes());
    }

    // Load and Store Instructions	op0	1	op1	0	op2		op3		op4
    pub(crate) fn ld_constant(state: &mut State, tmp: u32, imm: i64) -> Result<(), Error> {
        let c = imm.to_le_bytes();
        let pos = state.constant(&c);
        let loc = state.code.len();
        state.code.extend((0x58000000 | tmp).to_le_bytes());
        state.fixups.push((loc, crate::Fixup::Const(pos, 0)));
        Ok(())
    }

    // Data Processing — Register	sf	op0		op1	1	0	1	op2		op3
    // https://developer.arm.com/documentation/ddi0602/2025-03/Index-by-Encoding/Data-Processing----Register
    pub fn reg_shifted(
        state: &mut State,
        op: u32,
        shift: u32,
        rm: u32,
        imm6: u32,
        rn: u32,
        rd: u32,
    ) -> Result<(), Error> {
        let opcode = op | shift << 22 | rm << 16 | imm6 << 10 | rn << 5 | rd;
        state.code.extend(opcode.to_le_bytes());
        Ok(())
    }

    // Data Processing — Floating Point and SIMD	op0	1	1	1	op1	op2	op3
    pub fn fp_simd(state: &mut State) -> Result<(), Error> {
        Ok(())
    }

    pub fn adr(state: &mut State, dest: u32, label: u32) {
        state
            .fixups
            .push((state.code.len(), Fixup::Adr(super::regs::X0, label)));

        state.code.extend((OP_ADR | dest).to_le_bytes());
    }
}

#[cfg(test)]
mod tests;

mod bitconst;
