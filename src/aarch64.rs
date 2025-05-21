use crate::{
    CallInfo, Cond, CpuInfo, CpuLevel, EntryInfo, Error, Executable, Fixup, Ins, PcRel4, RegClass, Scale, Src, State, Type, Vsize, R
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

/// A simlified CPU level specification.
pub fn cpu_info() -> CpuInfo {
    // TODO:
    let cpu_level = CpuLevel::Simd128;

    // pre-allocate SP
    let alloc0 = 1 << SP.0;
    // Note for avx512, we will have 32 vector registers.
    let max_regs = [16, 16];

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
    use regs::*;
    CpuInfo {
        cpu_level,
        alloc: [alloc0, 0],
        max_regs,
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
const OP_SUBS: Optype = 0xeb000000;
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

impl Executable {
    pub fn from_ir(ins: &[Ins]) -> Result<Executable, Error> {
        Self::from_ir_and_info(ins, cpu_info())
    }

    pub fn from_ir_and_info(ins: &[Ins], cpu_info: CpuInfo) -> Result<Executable, Error> {
        let mut state = State {
            code: Vec::new(),
            labels: Vec::new(),
            constants: Vec::new(),
            fixups: Vec::new(),
            cpu_info,
        };
        for i in ins {
            use Ins::*;
            match i {
                Add(dest, src1, src2) => gen_binary(&mut state, OP_ADDS, dest, src1, src2, &i)?,
                Sub(dest, src1, src2) => gen_binary(&mut state, OP_SUBS, dest, src1, src2, &i)?,
                Adc(dest, src1, src2) => gen_binary(&mut state, OP_ADCS, dest, src1, src2, &i)?,
                Sbb(dest, src1, src2) => gen_binary(&mut state, OP_SBCS, dest, src1, src2, &i)?,
                And(dest, src1, src2) => gen_binary(&mut state, OP_ANDS, dest, src1, src2, &i)?,
                Or(dest, src1, src2) => gen_binary(&mut state, OP_ORR, dest, src1, src2, &i)?,
                Xor(dest, src1, src2) => gen_binary(&mut state, OP_EOR, dest, src1, src2, &i)?,
                Mul(dest, src1, src2) => gen_binary(&mut state, OP_MUL, dest, src1, src2, &i)?,
                Udiv(dest, src1, src2) => gen_binary(&mut state, OP_UDIV, dest, src1, src2, &i)?,
                Sdiv(dest, src1, src2) => gen_binary(&mut state, OP_SDIV, dest, src1, src2, &i)?,
                Not(dest, src) => gen_unary(&mut state, OP_MVN, dest, src, &i)?,
                Neg(dest, src) => gen_unary(&mut state, OP_NEG, dest, src, &i)?,
                Mov(dest, src) => gen_mov(&mut state, dest, src, &i)?,
                Cmp(src1, src2) => gen_unary(&mut state, OP_CMP, src1, src2, &i)?,
                Shl(dest, src1, src2) => gen_binary(&mut state, OP_LSL, dest, src1, src2, &i)?,
                Shr(dest, src1, src2) => gen_binary(&mut state, OP_LSR, dest, src1, src2, &i)?,
                Sar(dest, src1, src2) => gen_binary(&mut state, OP_ASR, dest, src1, src2, &i)?,
                Label(label) => state.labels.push((*label, state.code.len())),
                Addr(dest, label) => gen::adr(&mut state, dest.to_arm64(), *label),
                Ci(dest) => gen::branch_indirect(&mut state, OP_BLR, dest.to_arm64()),
                Bi(dest) => gen::branch_indirect(&mut state, OP_BR, dest.to_arm64()),
                Br(cond, label) => gen::branch_cond(&mut state, cond.to_arm64(), *label),
                Jmp(label) => gen::branch(&mut state, OP_B, *label),
                //     // state
                //     //     .fixups
                //     //     .push((state.code.len() + 1, Fixup::Label(*label, 4)));
                //     // state.code.extend([OP_JMP, 0, 0, 0, 0]);
                // }
                // Ret => {
                //     // state.code.push(0xc3);
                // }
                // Cmov(cond, dest, src) => {
                //     // if let Some(src) = src.as_gpr() {
                //     //     let op = cond.cc() + 0x40;
                //     //     gen_regreg(&mut state, op, dest, &src);
                //     // } else {
                //     //     return Err(Error::InvalidSrcArgument(i.clone()));
                //     // }
                // }
                // Enter(info) => {
                //     gen_enter(&mut state, &info, i)?;
                // }
                // Leave(info) => {
                //     gen_leave(&mut state, &info, i)?;
                // }
                // Ld(ty, r, ra, imm) => {
                //     gen_load(&mut state, *ty, *r, *ra, *imm, i)?;
                // }
                // St(ty, r, ra, imm) => {
                //     gen_store(&mut state, *ty, *r, *ra, *imm, i)?;
                // }
                // D(ty, value) => match ty {
                //     Type::U8 => state.code.extend([*value as u8]),
                //     Type::U16 => state.code.extend((*value as u16).to_le_bytes()),
                //     Type::U32 => state.code.extend((*value as u32).to_le_bytes()),
                //     Type::U64 => state.code.extend((*value as u64).to_le_bytes()),
                //     _ => return Err(Error::InvalidDataType(i.clone())),
                // },
                // Vld(_, vsize, v, ra, imm) => {
                //     gen_vload_store(&mut state, *vsize, OP_VLD, v, ra, *imm, i);
                // }
                // Vst(_, vsize, v, ra, imm) => {
                //     gen_vload_store(&mut state, *vsize, OP_VST, v, ra, *imm, i);
                // }
                // Vadd(ty, vsize, v, v1, v2) => {
                //     gen_vop(&mut state, &OP_VADD, ty, *vsize, v, v1, v2, i)?;
                // }
                // Vsub(ty, vsize, v, v1, v2) => {
                //     gen_vop(&mut state, &OP_VSUB, ty, *vsize, v, v1, v2, i)?;
                // }
                // Vand(ty, vsize, v, v1, v2) => {
                //     gen_vop(&mut state, &OP_VAND, ty, *vsize, v, v1, v2, i)?;
                // }
                // Vor(ty, vsize, v, v1, v2) => {
                //     gen_vop(&mut state, &OP_VOR, ty, *vsize, v, v1, v2, i)?;
                // }
                // Vxor(ty, vsize, v, v1, v2) => {
                //     gen_vop(&mut state, &OP_VXOR, ty, *vsize, v, v1, v2, i)?;
                // }
                // Vshl(ty, vsize, v, v1, v2) => {
                //     gen_vop(&mut state, &OP_VSHL, ty, *vsize, v, v1, v2, i)?;
                // }
                // Vshr(ty, vsize, v, v1, v2) => match ty {
                //     Type::U16 | Type::U32 | Type::U64 => {
                //         gen_vop(&mut state, &OP_VSHR, ty, *vsize, v, v1, v2, i)?
                //     }
                //     Type::S16 | Type::S32 | Type::S64 => {
                //         gen_vop(&mut state, &OP_VSAR, ty, *vsize, v, v1, v2, i)?
                //     }
                //     _ => return Err(Error::UnsupportedVectorOperation(i.clone())),
                // },
                // Vmul(ty, vsize, v, v1, v2) => {
                //     gen_vop(&mut state, &OP_VMUL, ty, *vsize, v, v1, v2, i)?;
                // }
                // Vmov(ty, vsize, v, v1) => {
                //     gen_vop(&mut state, &OP_VMOV, ty, *vsize, v, &R(0), v1, i)?;
                // }
                // Vrecpe(ty, vsize, v, v1) => {
                //     gen_vop(&mut state, &OP_VRCP, ty, *vsize, v, &R(0), v1, i)?;
                // }
                // Vrsqrte(ty, vsize, v, v1) => {
                //     gen_vop(&mut state, &OP_VRSQRT, ty, *vsize, v, &R(0), v1, i)?;
                // }
                // Call(call_info) => {
                //     gen_call(&mut state, call_info, i)?;
                // }
                // CallLocal(label) => {
                //     state
                //         .fixups
                //         .push((state.code.len() + 1, Fixup::Label(*label, 4)));
                //     state.code.extend([OP_CALL, 0, 0, 0, 0]);
                // }
                // Push(src) => gen_push(&mut state, src, i)?,
                // Pop(dest) => gen_pop(&mut state, dest, i)?,
                _ => todo!("{ins:?}"),
            }
        }

        let cbase = state.code.len();
        state.code.extend(&state.constants);

        for (loc, f) in state.fixups {
            let opcode: u32 = u32::from_le_bytes(state.code[loc..loc + 4].try_into().unwrap());
            match f {
                Fixup::Adr(dest, label) => {
                    if let Some((_, offset)) = state.labels.iter().find(|(n, _)| *n == label) {
                        let delta = *offset as isize - loc as isize;
                        if delta < -(1 << 20) || delta >= (1 << 20) {
                            return Err(Error::InvalidOffset);
                        }
                        let immhi = ((delta >> 2) & (1 << 19) - 1) as u32;
                        let immlo = (delta & 3) as u32;
                        // https://developer.arm.com/documentation/ddi0602/2025-03/Base-Instructions/ADR--Form-PC-relative-address-?lang=en
                        let opcode = opcode | immlo << 29 | immhi << 5;
                        state.code[loc..loc + 4].copy_from_slice(&opcode.to_le_bytes());
                    } else {
                        return Err(Error::MissingLabel(label));
                    }
                }
                Fixup::B(cond, label) => {
                    unimplemented!()
                }
                Fixup::Label(label, delta) => {
                    unimplemented!()
                }
                Fixup::Const(pos, delta) => {
                    let opcode: u32 =
                        u32::from_le_bytes(state.code[loc..loc + 4].try_into().unwrap());
                    let offset: i32 = ((cbase + pos) as isize - loc as isize - delta)
                        .try_into()
                        .map_err(|_| Error::CodeTooBig)?;
                    if offset % 4 != 0 || offset < -0x100000 || offset >= 0x100000 {
                        return Err(Error::InvalidOffset);
                    }
                    let offset = ((offset >> 2) & (1 << 19) - 1) as u32;
                    let opcode = opcode | offset << 5;
                    state.code[loc..loc + 4].copy_from_slice(&opcode.to_le_bytes());
                }
                // eg. sssss:imm19:00 => op | 00000:imm19:00000
                //     bits=19     rshift                 lshift
                Fixup::PcRel4(PcRel4{ label, offset, bits, lshift, rshift, delta }) => {
                    if let Some((_, offset)) = state.labels.iter().find(|(n, _)| *n == label) {
                        let delta = *offset as isize - loc as isize - delta;
                        if delta < -(1 << bits-1) || delta >= (1 << bits-1) {
                            return Err(Error::InvalidOffset);
                        }
                        if (delta >> rshift << rshift) != delta {
                            return Err(Error::InvalidOffset);
                        }
                        let mask = if bits >= 32 { !0 } else { (1<<bits)-1 };
                        let imm : u32 = ((delta >> rshift) & mask)
                            .try_into().map_err(|_| Error::InvalidOffset)?;
                        let opcode = opcode | imm << lshift;
                        state.code[loc..loc + 4].copy_from_slice(&opcode.to_le_bytes());
                    } else {
                        return Err(Error::MissingLabel(label));
                    }
                }
            }
        }
        Ok(Executable::new(&state.code, state.labels))
    }
}

fn gen_store(state: &mut State, ty: Type, r: R, ra: R, imm: i32, i: &Ins) -> Result<(), Error> {
    // use Type::*;
    // let (op, pfx_66, w) = match ty {
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

fn gen_enter(state: &mut State, info: &EntryInfo, i: &Ins) -> Result<(), Error> {
    // for r in &info.saves {
    //     gen_push(state, &r.into(), i)?;
    // }

    // let args_src : Box<[R]> = state.cpu_info.args().iter().take(info.args.len()).cloned().collect();
    // gen_movm(state, &info.args, &args_src, i)?;

    // if info.stack_size != 0 {
    //     let imm = &info.stack_size.into();
    //     gen_binary(state, OP_SUB, &regs::RSP, &regs::RSP, imm, i)?;
    // }
    Ok(())
}

fn gen_leave(state: &mut State, info: &EntryInfo, i: &Ins) -> Result<(), Error> {
    // if info.stack_size != 0 {
    //     let imm = &info.stack_size.into();
    //     gen_binary(state, OP_ADD, &regs::RSP, &regs::RSP, imm, i)?;
    // }

    // let res_dest : Box<[R]> = state.cpu_info.res().iter().take(info.res.len()).cloned().collect();

    // gen_movm(state, &res_dest, &info.res, i)?;

    // for r in info.saves.iter().rev() {
    //     gen_pop(state, &r.into(), i)?;
    // }
    Ok(())
}

/// Multiple register move. Typically arguments of functions.
/// Move the source register to the dest, avoiding dependencies.
///
/// eg.
///
///   No dependencies
///   gen_movm(&[R(2), R(3)], &[R(1), R(0)]);
///
///   We cannot do this with moves alone. (ideally use xchg or push/pop)
///   gen_movm(&[R(0), R(1)], &[R(1), R(0)]);
///
///   
fn gen_movm(state: &mut State, dest: &[R], src: &[R], i: &Ins) -> Result<(), Error> {
    let mut pops = Vec::new();
    for j in 0..dest.len() {
        let d = dest[j];
        let s = src[j];
        if d != s {
            if src[j + 1..].contains(&d) {
                gen_push(state, &s.into(), i)?;
                pops.push(d);
            } else {
                gen_mov(state, &d, &s.into(), i)?;
            }
        }
    }
    for d in pops.into_iter().rev() {
        gen_pop(state, &d.into(), i)?;
    }
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

    pub fn rc(&self) -> RegClass {
        if self.0 <= regs::SP.0 {
            RegClass::GPR
        } else if self.0 >= regs::V0.0 && self.0 <= regs::V31.0 {
            RegClass::VREG
        } else {
            RegClass::Unknown
        }
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
    if dest.rc() != RegClass::GPR || src1.rc() != RegClass::GPR {
        return Err(Error::BadRegClass(i.clone()));
    }
    if let Some(src2) = src2.as_gpr() {
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

fn gen_unary(state: &mut State, op: u32, dest: &R, src: &Src, i: &Ins) -> Result<(), Error> {
    if let Some(src) = src.as_gpr() {
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

fn gen_mov(state: &mut State, dest: &R, src: &Src, i: &Ins) -> Result<(), Error> {
    if dest.rc() != RegClass::GPR {
        return Err(Error::BadRegClass(i.clone()));
    }
    if let Some(r) = src.as_gpr() {
        if &r != dest {
            gen_unary(state, OP_MOV, dest, src, i);
        }
    } else if let Some(imm) = src.as_imm64() {
        gen::ld_constant(state, dest.to_arm64(), imm);
    } else {
        return Err(Error::InvalidSrcArgument(i.clone()));
    }
    Ok(())
}

/// The push instruction on x86 is quite efficient and is great
/// fo constant generation.
fn gen_push(state: &mut State, src: &Src, i: &Ins) -> Result<(), Error> {
    // if let Some(src) = src.as_gpr() {
    //     if src.rc() != RegClass::GPR {
    //         return Err(Error::BadRegClass(i.clone()));
    //     }
    //     let op = OP_PUSH + src.to_x86_low();
    //     if src.to_x86_high() == 0 {
    //         state.code.extend([op]);
    //     } else {
    //         let rex = 0x40 + src.to_x86_high();
    //         state.code.extend([rex, op]);
    //     }
    // } else if let Some(imm) = src.as_imm8() {
    //     state.code.extend([OP_PUSH8, imm.to_le_bytes()[0]]);
    // } else if let Some(imm) = src.as_imm32() {
    //     let imm = imm.to_le_bytes();
    //     state
    //         .code
    //         .extend([OP_PUSH32, imm[0], imm[1], imm[2], imm[3]]);
    // } else if let Some(imm) = src.as_imm64() {
    //     let imm = imm.to_le_bytes();
    //     state
    //         .code
    //         .extend([OP_PFX_66, OP_PUSH32, imm[0], imm[1], imm[2], imm[3]]);
    //     state
    //         .code
    //         .extend([OP_PFX_66, OP_PUSH32, imm[4], imm[5], imm[6], imm[7]]);
    // } else {
    //     return Err(Error::InvalidSrcArgument(i.clone()));
    // }
    Ok(())
}

fn gen_pop(state: &mut State, dest: &Src, i: &Ins) -> Result<(), Error> {
    // if let Some(dest) = dest.as_gpr() {
    //     if dest.rc() != RegClass::GPR {
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
mod tests {
    use crate::{regs, Cond, Executable, Ins};

    use super::bitconst;

    #[test]
    fn test_binary() {
        use regs::*;
        use Ins::*;
        let prog = Executable::from_ir(&[
            Add(X1, X2, X3.into()),
            Sub(X1, X2, X3.into()),
            Adc(X1, X2, X3.into()),
            Sbb(X1, X2, X3.into()),
            And(X1, X2, X3.into()),
            Or(X1, X2, X3.into()),
            Xor(X1, X2, X3.into()),
            Shl(X1, X2, X3.into()),
            Shr(X1, X2, X3.into()),
            Sar(X1, X2, X3.into()),
            Mul(X1, X2, X3.into()),
            Udiv(X1, X2, X3.into()),
            Sdiv(X1, X2, X3.into()),
            Add(X1, X2, 0x0.into()),
            Sub(X1, X2, 0x0.into()),
            Adc(X1, X2, 0x0.into()),
            Sbb(X1, X2, 0x0.into()),
            And(X1, X2, 0x0.into()),
            Or(X1, X2, 0x0.into()),
            Xor(X1, X2, 0x0.into()),
            Shl(X1, X2, 0x0.into()),
            Shr(X1, X2, 0x0.into()),
            Sar(X1, X2, 0x0.into()),
            Mul(X1, X2, 0x0.into()),
            Udiv(X1, X2, 0x0.into()),
            Sdiv(X1, X2, 0x0.into()),
            Add(X1, X2, 0x123.into()),
            Sub(X1, X2, 0x123.into()),
            Adc(X1, X2, 0x123.into()),
            Sbb(X1, X2, 0x123.into()),
            And(X1, X2, 0x123.into()),
            Or(X1, X2, 0x123.into()),
            Xor(X1, X2, 0x123.into()),
            Shl(X1, X2, 0x123.into()),
            Shr(X1, X2, 0x123.into()),
            Sar(X1, X2, 0x123.into()),
            Mul(X1, X2, 0x123.into()),
            Udiv(X1, X2, 0x123.into()),
            Sdiv(X1, X2, 0x123.into()),
            Add(X1, X2, 0x123000.into()),
            Sub(X1, X2, 0x123000.into()),
        ])
        .unwrap();
        assert_eq!(
            prog.fmt_url(),
            "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=48+01+c0+48+29+c0+48+21+c0+48+09+c0+48+31+c0+51+48+89+c1+48+d3+e0+59+51+48+89+c1+48+d3+e8+59+51+48+89+c1+48+d3+f8+59+48+0f+af+c0+52+50+31+d2+48+f7+34+24+48+83+c4+08+5a+52+50+48+99+48+f7+3c+24+48+83+c4+08+5a&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
        );
    }

    #[test]
    fn test_unary() {
        use regs::*;
        use Ins::*;
        let prog = Executable::from_ir(&[
            Mov(X1, X2.into()),
            Not(X1, X2.into()),
            Neg(X1, X2.into()),
            Cmp(X1, X2.into()),
            Mov(X1, 123.into()),
            Not(X1, 123.into()),
            Neg(X1, 123.into()),
            Cmp(X1, 123.into()),
        ])
        .unwrap();
        assert_eq!(
            prog.fmt_url(),
            "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=e10302aa+e10322aa+e10302cb+3f0002eb+a1000058+c1000058+e1000058+48000058+3f0008eb+7b000000+00000000+84ffffff+ffffffff+85ffffff+ffffffff&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
        );
    }

    #[test]
    fn test_misc() {
        use regs::*;
        use Ins::*;
        use Cond::*;
        let prog = Executable::from_ir(&[
            Addr(X1, 1),
            Addr(X1, 1),
            Label(1),
            Addr(X1, 1),
            Addr(X1, 1),

            Ci(X1),
            Bi(X1),

            Jmp(2),
            Jmp(2),
            Label(2),
            Jmp(2),
            Jmp(2),

            Br(Eq, 3),
            Br(Ne, 3),
            Br(Sgt, 3),
            Br(Sge, 3),
            Br(Slt, 3),
            Label(3),
            Br(Sle, 3),
            Br(Ugt, 3),
            Br(Uge, 3),
            Br(Ult, 3),
            Br(Ule, 3),
        ])
        .unwrap();
        assert_eq!(
            prog.fmt_url(),
            "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=41000010+21000010+01000010+e1ffff10+20003fd6+20001fd6+02000014+01000014+00000014+ffffff17+a0000054+81000054+6c000054+4a000054+2b000054+0d000054+e8ffff54+c2ffff54+a3ffff54+89ffff54&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
        );
    }
}

mod bitconst;
