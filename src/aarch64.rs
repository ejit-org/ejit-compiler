//! See 

use crate::{
    CallInfo, Compiler, CompilerResult, Cond, CpuInfo, CpuLevel, EntryInfo, Error, Executable,
    Fixup, Ins, PcRel, RegClass, RegInfo, Scale, Src, State, Type, Vsize, R,
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
const REG_INFO: &[RegInfo] = &[
    // x0-x7
    RegInfo::new(RegClass::GPR, false, false, false, Some(0), Some(0), "x0"),
    RegInfo::new(RegClass::GPR, false, false, false, Some(1), Some(1), "x1"),
    RegInfo::new(RegClass::GPR, false, false, false, Some(2), Some(2), "x2"),
    RegInfo::new(RegClass::GPR, false, false, false, Some(3), Some(3), "x3"),
    RegInfo::new(RegClass::GPR, false, false, false, Some(4), Some(4), "x4"),
    RegInfo::new(RegClass::GPR, false, false, false, Some(5), Some(5), "x5"),
    RegInfo::new(RegClass::GPR, false, false, false, Some(6), Some(6), "x6"),
    RegInfo::new(RegClass::GPR, false, false, false, Some(7), Some(7), "x7"),
    // x8-x15
    RegInfo::new(RegClass::GPR, false, false, true, None, None, "x8"),
    RegInfo::new(RegClass::GPR, false, true, false, None, None, "x9"),
    RegInfo::new(RegClass::GPR, false, true, false, None, None, "x10"),
    RegInfo::new(RegClass::GPR, false, true, false, None, None, "x11"),
    RegInfo::new(RegClass::GPR, false, true, false, None, None, "x12"),
    RegInfo::new(RegClass::GPR, false, true, false, None, None, "x13"),
    RegInfo::new(RegClass::GPR, false, true, false, None, None, "x14"),
    RegInfo::new(RegClass::GPR, false, true, false, None, None, "x15"),
    // x16-x23
    RegInfo::new(RegClass::GPR, false, false, false, None, None, "x16"),
    RegInfo::new(RegClass::GPR, false, false, false, None, None, "x17"),
    RegInfo::new(RegClass::GPR, false, false, true, None, None, "x18"),
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x19"),
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x20"),
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x21"),
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x22"),
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x23"),
    // x24-x31
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x24"),
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x25"),
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x26"),
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x27"),
    RegInfo::new(RegClass::GPR, true, true, false, None, None, "x28"),
    RegInfo::new(RegClass::GPR, true, false, false, None, None, "x29"),
    RegInfo::new(RegClass::GPR, true, false, true, None, None, "x30"),
    RegInfo::new(RegClass::GPR, true, false, true, None, None, "x31"),
    // v0-v7
    RegInfo::new(RegClass::VREG, false, false, false, Some(0), Some(0), "v0"),
    RegInfo::new(RegClass::VREG, false, false, false, Some(1), Some(1), "v1"),
    RegInfo::new(RegClass::VREG, false, false, false, Some(2), Some(2), "v2"),
    RegInfo::new(RegClass::VREG, false, false, false, Some(3), Some(3), "v3"),
    RegInfo::new(RegClass::VREG, false, false, false, Some(4), Some(4), "v4"),
    RegInfo::new(RegClass::VREG, false, false, false, Some(5), Some(5), "v5"),
    RegInfo::new(RegClass::VREG, false, false, false, Some(6), Some(6), "v6"),
    RegInfo::new(RegClass::VREG, false, false, false, Some(7), Some(7), "v7"),
    // v8-v15
    RegInfo::new(RegClass::VREG, true, true, false, None, None, "v8"),
    RegInfo::new(RegClass::VREG, true, true, false, None, None, "v9"),
    RegInfo::new(RegClass::VREG, true, true, false, None, None, "v10"),
    RegInfo::new(RegClass::VREG, true, true, false, None, None, "v11"),
    RegInfo::new(RegClass::VREG, true, true, false, None, None, "v12"),
    RegInfo::new(RegClass::VREG, true, true, false, None, None, "v13"),
    RegInfo::new(RegClass::VREG, true, true, false, None, None, "v14"),
    RegInfo::new(RegClass::VREG, true, true, false, None, None, "v15"),
    // v16-v23
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v16"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v17"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v18"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v19"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v20"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v21"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v22"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v23"),
    // v24-v31
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v24"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v25"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v26"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v27"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v28"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v29"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v30"),
    RegInfo::new(RegClass::VREG, false, true, false, None, None, "v31"),
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
const OP_BL : Optype = 0x94000000; // 	bl <label>

/// https://developer.arm.com/documentation/ddi0602/2024-03/Base-Instructions/LDR--literal---Load-Register--literal--
const OP_LDR_LITERAL_U64 : Optype = 0x58000000; //  ldr x0, <label>
const OP_LDR_LITERAL_V32 : Optype = 0x1c000000; //  ldr s0, <label>
const OP_LDR_LITERAL_V64 : Optype = 0x5c000000; //  ldr d0, <label>
const OP_LDR_LITERAL_V128 : Optype = 0x9c000000; //  ldr q0, <label>

const OP_LD_U8_R_IMM12: Optype = 0x39400000; // 	ldrb	w0, [x0]
const OP_LD_U8_R_R: Optype = 0x38606800; // 	ldrb	w0, [x0, x0]
const OP_LD_U16_R_IMM12: Optype = 0x79400000; // 	ldrh	w0, [x0]
const OP_LD_U16_R_R: Optype = 0x78606800; // 	ldrh	w0, [x0, x0]
const OP_LD_U32_R_IMM12: Optype = 0xb9400000; // 	ldr	w0, [x0]
const OP_LD_U32_R_R: Optype = 0xb8606800; // 	ldr	w0, [x0, x0]
const OP_LD_U64_R_IMM12: Optype = 0xf9400000; // 	ldr	x0, [x0]
const OP_LD_U64_R_R: Optype = 0xf8606800; // 	ldr	x0, [x0, x0]
const OP_LD_S8_R_IMM12 : Optype = 0x39c00000; // 	ldrsb	w0, [x0]
const OP_LD_S8_R_R : Optype = 0x38e06800; // 	ldrsb	w0, [x0, x0]
const OP_LD_S16_R_IMM12 : Optype = 0x79c00000; // 	ldrsh	w0, [x0]
const OP_LD_S16_R_R : Optype = 0x78e06800; // 	ldrsh	w0, [x0, x0]
const OP_LD_S32_R_IMM12 : Optype = 0xb9800000; // 	ldrsw	x0, [x0]
const OP_LD_S32_R_R : Optype = 0xb8a06800; // 	ldrsw	x0, [x0, x0]
const OP_LD_S64_R_IMM12 : Optype = 0xf9400000; // 	ldr	x0, [x0]
const OP_LD_S64_R_R : Optype = 0xf8606800; // 	ldr	x0, [x0, x0]
const OP_ST_8_R_IMM12 : Optype = 0x39000000; // 	strb	w0, [x0]
const OP_ST_8_R_R : Optype = 0x38206800; // 	strb	w0, [x0, x0]
const OP_ST_16_R_IMM12 : Optype = 0x79000000; // 	strh	w0, [x0]
const OP_ST_16_R_R : Optype = 0x78206800; // 	strh	w0, [x0, x0]
const OP_ST_32_R_IMM12 : Optype = 0xb9000000; // 	str	w0, [x0]
const OP_ST_32_R_R : Optype = 0xb8206800; // 	str	w0, [x0, x0]
const OP_ST_64_R_IMM12 : Optype = 0xf9000000; // 	str	x0, [x0]
const OP_ST_64_R_R : Optype = 0xf8206800; // 	str	x0, [x0, x0]

const OP_PUSH : Optype = 0xf81f8fe0; // 	str	x0, [sp, #-8]!
const OP_POP : Optype = 0xf84087e0; // 	ldr	x0, [sp], #8

// auto
const OP_AND_V8 : Optype = 0x0e201c00; // and	v0.8b, v0.8b, v0.8b
const OP_AND_V16 : Optype = 0x4e201c00; // and	v0.16b, v0.16b, v0.16b
const OP_ORR_V8 : Optype = 0x0ea01c00; // mov	v0.8b, v0.8b
const OP_ORR_V16 : Optype = 0x4ea01c00; // mov	v0.16b, v0.16b
const OP_EOR_V8 : Optype = 0x2e201c00; // eor	v0.8b, v0.8b, v0.8b
const OP_EOR_V16 : Optype = 0x6e201c00; // eor	v0.16b, v0.16b, v0.16b
const OP_LSL_V8B_IMM : Optype = 0x0f085400; // shl	v0.8b, v0.8b, #0
const OP_LSL_V16B_IMM : Optype = 0x4f085400; // shl	v0.16b, v0.16b, #0
const OP_LSL_V4H_IMM : Optype = 0x0f105400; // shl	v0.4h, v0.4h, #0
const OP_LSL_V8H_IMM : Optype = 0x4f105400; // shl	v0.8h, v0.8h, #0
const OP_LSL_V2S_IMM : Optype = 0x0f205400; // shl	v0.2s, v0.2s, #0
const OP_LSL_V4S_IMM : Optype = 0x4f205400; // shl	v0.4s, v0.4s, #0
const OP_LSL_V2D_IMM : Optype = 0x4f405400; // shl	v0.2d, v0.2d, #0
const OP_RET : Optype = 0xd65f03c0; // ret

const OP_VADD : &[(Type, Vsize, Optype)] = &[
    (Type::U8, Vsize::V64, 0x0e208400), // 	add	v0.8b, v0.8b, v0.8b
    (Type::U8, Vsize::V128, 0x4e208400), // 	add	v0.16b, v0.16b, v0.16b
    (Type::U16, Vsize::V64, 0x0e608400), // 	add	v0.4h, v0.4h, v0.4h
    (Type::U16, Vsize::V128, 0x4e608400), // 	add	v0.8h, v0.8h, v0.8h
    (Type::U32, Vsize::V64, 0x0ea08400), // 	add	v0.2s, v0.2s, v0.2s
    (Type::U32, Vsize::V128, 0x4ea08400), // 	add	v0.4s, v0.4s, v0.4s
    (Type::U64, Vsize::V128, 0x4ee08400), // 	add	v0.2d, v0.2d, v0.2d
    (Type::F32, Vsize::V32, 0x1e202800), // 	fadd	s0, s0, s0
    (Type::F64, Vsize::V64, 0x1e602800), // 	fadd	d0, d0, d0
    (Type::F32, Vsize::V64, 0x0e20d400), // 	fadd	v0.2s, v0.2s, v0.2s
    (Type::F32, Vsize::V128, 0x4e20d400), // 	fadd	v0.4s, v0.4s, v0.4s
    (Type::F64, Vsize::V128, 0x4e60d400), // 	fadd	v0.2d, v0.2d, v0.2d
];

const OP_VSUB : &[(Type, Vsize, Optype)] = &[
    (Type::U8, Vsize::V64, 0x2e208400), // sub	v0.8b, v0.8b, v0.8b
    (Type::U8, Vsize::V128, 0x6e208400), // sub	v0.16b, v0.16b, v0.16b
    (Type::U16, Vsize::V64, 0x2e608400), // sub	v0.4h, v0.4h, v0.4h
    (Type::U16, Vsize::V128, 0x6e608400), // sub	v0.8h, v0.8h, v0.8h
    (Type::U32, Vsize::V64, 0x2ea08400), // sub	v0.2s, v0.2s, v0.2s
    (Type::U32, Vsize::V128, 0x6ea08400), // sub	v0.4s, v0.4s, v0.4s
    (Type::U64, Vsize::V128, 0x6ee08400), // sub	v0.2d, v0.2d, v0.2d
    (Type::F32, Vsize::V32, 0x1e203800), // fsub	s0, s0, s0
    (Type::F64, Vsize::V64, 0x1e603800), // fsub	d0, d0, d0
    (Type::F32, Vsize::V64, 0x0ea0d400), // fsub	v0.2s, v0.2s, v0.2s
    (Type::F32, Vsize::V128, 0x4ea0d400), // fsub	v0.4s, v0.4s, v0.4s
    (Type::F64, Vsize::V128, 0x4ee0d400), // fsub	v0.2d, v0.2d, v0.2d
];

const OP_VAND : &[(Vsize, Optype)] = &[
    (Vsize::V64, OP_AND_V8),
    (Vsize::V128, OP_AND_V16),
];

const OP_VORR : &[(Vsize, Optype)] = &[
    (Vsize::V64, OP_ORR_V8),
    (Vsize::V128, OP_ORR_V16),
];

const OP_VEOR : &[(Vsize, Optype)] = &[
    (Vsize::V64, OP_EOR_V8),
    (Vsize::V128, OP_EOR_V16),
];

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

    fn addsub(
        &mut self,
        ops: [u32; 2],
        dest: R,
        src1: R,
        src2: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        let state = self.state();
        check_args(dest, src1, src2, i, state)?;
        Ok(if let Some(src2) = src2.as_gpr(&state.cpu_info) {
            let (rd, rn, rm) = (dest.to_arm64(), src1.to_arm64(), src2.to_arm64());
            gen::reg_shifted(state, ops[0], 0, rm, 0, rn, rd)?;
        } else if let Some(imm) = src2.as_imm64() {
            let (rd, rn) = (dest.to_arm64(), src1.to_arm64());
            if imm & !0xfff == 0 {
                gen::imm_shifted(state, ops[1], 0, imm as u32, rn, rd)?;
            } else if imm & !(0xfff << 12) == 0 {
                gen::imm_shifted(state, ops[1], 1, (imm >> 12) as u32, rn, rd)?;
            } else {
                gen::ld_constant(state, regs::TMP.to_arm64(), imm)?;
                gen::reg_shifted(state, ops[0], 0, regs::TMP.to_arm64(), 0, rn, rd)?;
            }
        } else {
            return Err(Error::InvalidSrcArgument(i.clone()));
        })
    }

    fn binary(&mut self, op: u32, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        let state = self.state();
        check_args(dest, src1, src2, i, state)?;
        Ok(if let Some(src2) = src2.as_gpr(&state.cpu_info) {
            let (rd, rn, rm) = (dest.to_arm64(), src1.to_arm64(), src2.to_arm64());
            gen::reg_shifted(state, op, 0, rm, 0, rn, rd)?;
        } else if let Some(imm) = src2.as_imm64() {
            let (rd, rn) = (dest.to_arm64(), src1.to_arm64());
            if imm == 0 {
                gen::reg_shifted(state, op, 0, regs::XZR.to_arm64(), 0, rn, rd)?;
            } else {
                gen::ld_constant(state, regs::TMP.to_arm64(), imm)?;
                gen::reg_shifted(state, op, 0, regs::TMP.to_arm64(), 0, rn, rd)?;
            }
        } else {
            return Err(Error::InvalidSrcArgument(i.clone()));
        })
    }

    fn unary(&mut self, op: u32, dest: R, src: &Src, ctxt: &'static str) -> Result<(), Error> {
        let state = self.state();
        if let Some(src) = src.as_gpr(&state.cpu_info) {
            if op == OP_CMP {
                let (rm, rn, rd) = (dest.to_arm64(), src.to_arm64(), regs::XZR.to_arm64());
                gen::reg_shifted(state, op, 0, rm, 0, rn, rd)?;
            } else {
                let (rm, rn, rd) = (src.to_arm64(), regs::XZR.to_arm64(), dest.to_arm64());
                gen::reg_shifted(state, op, 0, rm, 0, rn, rd)?;
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
                    self.unary(op, dest, &regs::TMP.into(), "cmp");
                }
                OP_MOV => {
                    gen::ld_constant(state, dest.to_arm64(), imm)?;
                }
                _ => unreachable!(),
            }
        } else {
            return Err(Error::InvalidSrcArgument2(ctxt));
        }
        Ok(())
    }
    
    fn vbinary_generic(&mut self, ops: &[(Type, Vsize, u32)], ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        if let Some((_, _, op)) = ops.iter().find(|(t, v, _)| *t == ty && *v == vsize) {
            self.vbinary(*op, ty, vsize, dest, src1, src2, i)
        } else {
            Err(Error::InvalidType(i.clone()))
        }
    }
    
    fn vbinary_size_only(&mut self, ops: &[(Vsize, u32)], ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        if let Some((_, op)) = ops.iter().find(|(v, _)| *v == vsize) {
            self.vbinary(*op, ty, vsize, dest, src1, src2, i)
        } else {
            Err(Error::InvalidType(i.clone()))
        }
    }
    
    fn vbinary(&mut self, op: u32, ty: Type, vsize: Vsize, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        let cpu_info = &self.state().cpu_info;
        if
            dest.rc(cpu_info) != RegClass::VREG ||
            src1.rc(cpu_info) != RegClass::VREG
        {
            return Err(Error::BadRegClass(i.clone()));
        }

        if let Some(src2) = src2.as_vreg(cpu_info) {
            gen::reg3(self.state(), op, dest.to_arm64(), src1.to_arm64(), src2.to_arm64());
        } else if src2.is_imm64() {
            todo!();
        } else {
            return Err(Error::InvalidSrcArgument(i.clone()));
        }
        Ok(())
    }
}

impl Compiler for Aarch64Compiler {
    fn state(&mut self) -> &mut State {
        &mut self.state
    }

    fn addr(&mut self, dest: R, label: u32, i: &Ins) -> Result<(), Error> {
        gen::adr(self.state(), dest.to_arm64(), label);
        Ok(())
    }

    fn ld(&mut self, ty: Type, r: R, ra: R, offset: i32, i: &Ins) -> Result<(), Error> {
        let (rn, rt) = (ra.to_arm64(), r.to_arm64());

        let (imm12_op, rr_op) = match ty {
            Type::U8 => (OP_LD_U8_R_IMM12, OP_LD_U8_R_R),
            Type::U16 => (OP_LD_U16_R_IMM12, OP_LD_U16_R_R),
            Type::U32 => (OP_LD_U32_R_IMM12, OP_LD_U32_R_R),
            Type::U64 => (OP_LD_U64_R_IMM12, OP_LD_U64_R_R),
            Type::S8 => (OP_LD_S8_R_IMM12, OP_LD_S8_R_R),
            Type::S16 => (OP_LD_S16_R_IMM12, OP_LD_S16_R_R),
            Type::S32 => (OP_LD_S32_R_IMM12, OP_LD_S32_R_R),
            Type::S64 => (OP_LD_S64_R_IMM12, OP_LD_S64_R_R),
            _ => {
                return Err(Error::InvalidType(i.clone()));
            }
        };

        let op = if offset >= 0 && offset < (1<<12+2) && offset % 4 == 0 {
            let imm12 = offset as u32 >> 2;
            imm12_op | imm12 << 10 | (rn << 5) | rt
        } else {
            // Fallback to loading the offset into a temporary register.
            let rm = regs::TMP.to_arm64();
            gen::ld_constant(self.state(), rm, offset as i64);
            rr_op | rm << 16 | (rn << 5) | rt
        };

        self.state().push4(op);
        Ok(())
    }

    fn st(&mut self, ty: Type, r: R, ra: R, offset: i32, i: &Ins) -> Result<(), Error> {
        let (rn, rt) = (ra.to_arm64(), r.to_arm64());

        let (imm12_op, rr_op) = match ty {
            Type::U8 => (OP_ST_8_R_IMM12, OP_ST_8_R_R),
            Type::U16 => (OP_ST_16_R_IMM12, OP_ST_16_R_R),
            Type::U32 => (OP_ST_32_R_IMM12, OP_ST_32_R_R),
            Type::U64 => (OP_ST_64_R_IMM12, OP_ST_64_R_R),
            Type::S8 => (OP_ST_8_R_IMM12, OP_ST_8_R_R),
            Type::S16 => (OP_ST_16_R_IMM12, OP_ST_16_R_R),
            Type::S32 => (OP_ST_32_R_IMM12, OP_ST_32_R_R),
            Type::S64 => (OP_ST_64_R_IMM12, OP_ST_64_R_R),
            _ => {
                return Err(Error::InvalidType(i.clone()));
            }
        };

        let op = if offset >= 0 && offset < (1<<12+2) && offset % 4 == 0 {
            let imm12 = offset as u32 >> 2;
            imm12_op | imm12 << 10 | (rn << 5) | rt
        } else {
            // Fallback to loading the offset into a temporary register.
            let rm = regs::TMP.to_arm64();
            gen::ld_constant(self.state(), rm, offset as i64);
            rr_op | rm << 16 | (rn << 5) | rt
        };

        self.state().push4(op);
        Ok(())
    }

    fn vld(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        offset: i32,
        i: &Ins,
    ) -> Result<(), Error> {
        todo!()
    }

    fn vst(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        offset: i32,
        i: &Ins,
    ) -> Result<(), Error> {
        todo!()
    }

    fn add(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.addsub([OP_ADDS, OP_ADDI], dest, src1, src2, i)
    }

    fn sub(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.addsub([OP_SUBS, OP_SUBI], dest, src1, src2, i)
    }

    fn adc(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_ADCS, dest, src1, src2, i)
    }

    fn sbb(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_SBCS, dest, src1, src2, i)
    }

    fn and(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_ANDS, dest, src1, src2, i)
    }

    fn or(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_ORR, dest, src1, src2, i)
    }

    fn xor(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_EOR, dest, src1, src2, i)
    }

    fn shl(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_LSL, dest, src1, src2, i)
    }

    fn shr(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_LSR, dest, src1, src2, i)
    }

    fn sar(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_ASR, dest, src1, src2, i)
    }

    fn mul(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_MUL, dest, src1, src2, i)
    }

    fn udiv(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_UDIV, dest, src1, src2, i)
    }

    fn sdiv(&mut self, dest: R, src1: R, src2: &Src, i: &Ins) -> Result<(), Error> {
        self.binary(OP_SDIV, dest, src1, src2, i)
    }

    fn mov<S: Into<Src>>(&mut self, dest: R, src: S) -> Result<&mut Self, Error> {
        let src = src.into();
        let state = self.state();
        if dest.rc(&state.cpu_info) != RegClass::GPR {
            return Err(Error::BadRegClass2("mov", dest));
        }
        if let Some(r) = src.as_gpr(&state.cpu_info) {
            if r != dest {
                self.unary(OP_MOV, dest, &src, "mov");
            }
        } else if let Some(imm) = src.as_imm64() {
            gen::ld_constant(state, dest.to_arm64(), imm);
        } else {
            return Err(Error::InvalidSrcArgument2("mov"));
        }
        Ok(self)
    }

    fn cmp(&mut self, dest: R, src: &Src, i: &Ins) -> Result<(), Error> {
        self.unary(OP_CMP, dest, src, "cmp")
    }

    fn not(&mut self, dest: R, src: &Src, i: &Ins) -> Result<(), Error> {
        self.unary(OP_MVN, dest, src, "not")
    }

    fn neg(&mut self, dest: R, src: &Src, i: &Ins) -> Result<(), Error> {
        self.unary(OP_NEG, dest, src, "neg")
    }

    fn push(&mut self, src: &Src, i: &Ins) -> Result<(), Error> {
        if let Some(r) = src.as_gpr(&self.state().cpu_info) {
            if r == regs::SP {
                return Err(Error::SpNotAllowed(i.clone()));
            }
            self.state().push4(OP_PUSH | r.to_arm64());
        } else {
            return Err(Error::InvalidSrcArgument(i.clone()));
        }
        Ok(())
    }

    fn pop(&mut self, src: &Src, i: &Ins) -> Result<(), Error> {
        if let Some(r) = src.as_gpr(&self.state().cpu_info) {
            if r == regs::SP {
                return Err(Error::SpNotAllowed(i.clone()));
            }
            self.state().push4(OP_POP | r.to_arm64());
        } else {
            return Err(Error::InvalidSrcArgument(i.clone()));
        }
        Ok(())
    }

    fn vadd(
        &mut self,
        ty: Type,
        vsize: Vsize,
        dest: R,
        src1: R,
        src2: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        self.vbinary_generic(OP_VADD, ty, vsize, dest, src1, src2, i)
    }

    fn vsub(
        &mut self,
        ty: Type,
        vsize: Vsize,
        dest: R,
        src1: R,
        src2: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        self.vbinary_generic(OP_VSUB, ty, vsize, dest, src1, src2, i)
    }

    fn vand(
        &mut self,
        ty: Type,
        vsize: Vsize,
        dest: R,
        src1: R,
        src2: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        self.vbinary_size_only(OP_VAND, ty, vsize, dest, src1, src2, i)
    }

    fn vor(
        &mut self,
        ty: Type,
        vsize: Vsize,
        dest: R,
        src1: R,
        src2: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        self.vbinary_size_only(OP_VORR, ty, vsize, dest, src1, src2, i)
    }

    fn vxor(
        &mut self,
        ty: Type,
        vsize: Vsize,
        dest: R,
        src1: R,
        src2: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        self.vbinary_size_only(OP_VEOR, ty, vsize, dest, src1, src2, i)
    }

    fn vshl(
        &mut self,
        ty: Type,
        vsize: Vsize,
        dest: R,
        src1: R,
        src2: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        todo!()
    }

    fn vshr(
        &mut self,
        ty: Type,
        vsize: Vsize,
        dest: R,
        src1: R,
        src2: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        todo!()
    }

    fn vmul(
        &mut self,
        ty: Type,
        vsize: Vsize,
        dest: R,
        src1: R,
        src2: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        todo!()
    }

    fn vmov(&mut self, ty: Type, vsize: Vsize, dest: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vrecpe(&mut self, ty: Type, vsize: Vsize, dest: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn vrsqrte(
        &mut self,
        ty: Type,
        vsize: Vsize,
        dest: R,
        src: &Src,
        i: &Ins,
    ) -> Result<(), Error> {
        todo!()
    }

    fn call_local(&mut self, value: u32, i: &Ins) -> Result<(), Error> {
        gen::branch(self.state(), OP_BL, value);
        Ok(())
    }

    fn call_abs(&mut self, loc: u64, i: &Ins) -> Result<(), Error> {
        let rm = regs::TMP.to_arm64();
        gen::ld_constant(self.state(), rm, loc as i64);
        gen::branch_indirect(self.state(), OP_BLR, rm);
        Ok(())
    }

    fn ci(&mut self, reg: R, i: &Ins) -> Result<(), Error> {
        let rm = reg.to_arm64();
        gen::branch_indirect(self.state(), OP_BLR, rm);
        Ok(())
    }

    fn bi(&mut self, reg: R, i: &Ins) -> Result<(), Error> {
        let rm = reg.to_arm64();
        gen::branch_indirect(self.state(), OP_BR, rm);
        Ok(())
    }

    fn br(&mut self, cond: Cond, value: u32, i: &Ins) -> Result<(), Error> {
        Ok(())
    }

    fn jmp(&mut self, value: u32, i: &Ins) -> Result<(), Error> {
        gen::branch(self.state(), OP_B, value);
        Ok(())
    }

    fn cmov(&mut self, cond: Cond, dest: R, src: &Src, i: &Ins) -> Result<(), Error> {
        todo!()
    }

    fn ret(&mut self) -> Result<&mut Self, Error> {
        self.state().push4(OP_RET);
        Ok(self)
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

impl R {
    pub fn to_arm64(&self) -> u32 {
        (self.0 & 0x1f ) as u32
    }
}

pub mod gen {
    use crate::{aarch64::OP_LDR_LITERAL_U64, Cond, Error, Fixup, LabelOrConst, PcRel, State, R};

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
        state.push4(opcode);
        Ok(())
    }

    // Branches + System Instructions	op0	1	0	1	op1		op2
    pub(crate) fn branch_indirect(state: &mut State, op: u32, reg: u32) {
        state.push4((op | reg << 5));
    }

    pub(crate) fn branch_cond(state: &mut State, cond: u32, label: u32) {
        let fixup = Fixup::PcRel(PcRel {
            target: LabelOrConst::Label(label),
            offset: 0,
            bits: 19,
            rshift: 2,
            lshift: 5,
            delta: 0,
        });
        state.fixups.push((state.code.len(), fixup));
        state.push4((OP_BCC | cond));
    }

    pub fn branch(state: &mut State, op: u32, label: u32) {
        let fixup = Fixup::PcRel(PcRel {
            target: LabelOrConst::Label(label),
            offset: 0,
            bits: 26,
            rshift: 2,
            lshift: 0,
            delta: 0,
        });
        state.fixups.push((state.code.len(), fixup));
        state.push4(op);
    }

    /// Generate a constant in a register.
    pub(crate) fn ld_constant(state: &mut State, dest: u32, imm: i64) -> Result<(), Error> {
        // TODO add  more options here.
        let c = imm.to_le_bytes();
        let pos = state.constant(&c);
        let loc = state.code.len();

        state.push4((OP_LDR_LITERAL_U64 | dest));

        let fixup = Fixup::PcRel(PcRel {
            target: LabelOrConst::Const(pos),
            offset: 0,
            bits: 19,
            rshift: 2,
            lshift: 5,
            delta: 0,
        });
        state.fixups.push((state.code.len(), fixup));
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
        state.push4(opcode);
        Ok(())
    }

    // Data Processing — Floating Point and SIMD	op0	1	1	1	op1	op2	op3
    pub fn fp_simd(state: &mut State) -> Result<(), Error> {
        Ok(())
    }

    pub fn adr(state: &mut State, dest: u32, label: u32) {
        todo!();
        // state
        //     .fixups
        //     .push((state.code.len(), Fixup::Adr(super::regs::X0, label)));

        // state.push4((OP_ADR | dest));
    }

    pub fn reg3(state: &mut State, op: u32, dest: u32, src1: u32, src2: u32) {
        let (rd, rn, rm) = (dest, src1, src2);
        state.push4(op | (rm << 16) | (rn << 5) | rd);
    }
}

#[cfg(test)]
mod tests;

mod bitconst;
