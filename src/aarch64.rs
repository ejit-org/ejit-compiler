use crate::{Cond, Error, Executable, Ins, Type, Vsize, R, V};

mod base;
mod vector;

pub mod regs {
    use crate::R;

    // See https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
    pub const ARG: [R; 8] = [R(0), R(1), R(2), R(3), R(4), R(5), R(6), R(7)];
    pub const RES: [R; 2] = [R(0), R(1)];
    pub const SP: R = R(31);
}

impl Executable {
    pub fn from_ir(ins: &[Ins]) -> Result<Executable, Error> {
        let mut code = Vec::new();
        let mut labels: Vec<(u32, usize)> = Vec::new();
        let mut fixups: Vec<(usize, Fixup)> = Vec::new();
        for i in ins {
            use Ins::*;
            // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions
            match i {
                Add(..) | Sub(..) | And(..) | Or(..) | Xor(..) | Shl(..) | Shr(..) | Sar(..) | Mul(..) | UDiv(..) | SDiv(..) | Not(..) | Neg(..) | Movi(..) | Mov(..)  | Cmpi(..) | Cmp(..) => {
                    base::gen_base_aarch64(&mut code, &i)?;
                }
                
                Label(label) => labels.push((*label, code.len())),

                Addr(dest, label) => {
                    fixups.push((code.len(), Fixup::Adr(*dest, *label)));
                    code.extend(0x10000000_u32.to_le_bytes());
                }
                Call(target) => {
                    let opcode = 0xd63f0000_u32 | target.to_aarch64() << 5;
                    code.extend(opcode.to_le_bytes());
                }
                Branch(target) => {
                    let opcode = 0xd61f0000_u32 | target.to_aarch64() << 5;
                    code.extend(opcode.to_le_bytes());
                }
                B(cond, label) => {
                    fixups.push((code.len(), Fixup::B(*cond, *label)));
                    code.extend(0x10000000_u32.to_le_bytes());
                }
                J(label) => {
                    fixups.push((code.len(), Fixup::J(*label)));
                    code.extend(0x14000000_u32.to_le_bytes());
                }
                Ret => {
                    code.extend(0xd65f03c0_u32.to_le_bytes());
                }
                Sel(cond, d, t, f) => {
                    let opcode: u32 = match cond {
                        Cond::Eq => 0x9a800000,
                        Cond::Ne => 0x9a801000,
                        Cond::Sgt => 0x9a80C000,
                        Cond::Sge => 0x9a80A000,
                        Cond::Slt => 0x9a80B000,
                        Cond::Sle => 0x9a80D000,
                        Cond::Ugt => 0x9a808000,
                        Cond::Uge => 0x9a802000,
                        Cond::Ult => 0x9a803000,
                        Cond::Ule => 0x9a809000,
                    };
                    let opcode =
                        opcode | f.to_aarch64() << 16 | t.to_aarch64() << 5 | d.to_aarch64();
                    code.extend(opcode.to_le_bytes());
                }
                Enter(imm) => {
                    // FF0300D1 	    sub sp, sp, #0
                    if *imm >= 0x1000 {
                        return Err(Error::InvalidImmediate(i.clone()));
                    }
                    if *imm & 0x0f != 0 {
                        return Err(Error::StackFrameMustBeModulo16(i.clone()));
                    }
                    let opcode = 0xd10003ff_u32 | (*imm as u32) << 10;
                    code.extend(opcode.to_le_bytes());
                }
                Leave(imm) => {
                    // FF030091 	    add sp, sp, #0
                    if *imm >= 0x1000 {
                        return Err(Error::InvalidImmediate(i.clone()));
                    }
                    if *imm & 0x0f != 0 {
                        return Err(Error::StackFrameMustBeModulo16(i.clone()));
                    }
                    let opcode = 0x910003ff_u32 | (*imm as u32) << 10;
                    code.extend(opcode.to_le_bytes());
                }
                Ld(ty, r, ra, imm) => {
                    // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions/LDR--register---Load-register--register--?lang=en
                    use Type::*;
                    let (shift, opcode) = match ty {
                        U8 => (0, 0x39400000),  // 00004039 	    ldrb w0, [x0, #0]
                        U16 => (1, 0x79400000), // 00004079 	    ldrh w0, [x0, #0]
                        U32 => (2, 0xb9400000), // 000040B9 	    ldr w0, [x0, #0]
                        U64 => (3, 0xf9400000), // 000040F9 	    ldr x0, [x0, #0]
                        S8 => (0, 0x39c00000),  // 0000C039 	    ldrsb w0, [x0, #0]
                        S16 => (1, 0x79c00000), // 0000C079 	    ldrsh w0, [x0, #0]
                        S32 => (2, 0xb9800000), // 000080B9 	    ldrsw x0, [x0, #0]
                        S64 => (3, 0xf9400000), // 000040F9 	    ldr x0, [x0, #0]
                        _ => return Err(Error::InvalidType(i.clone())),
                    };
                    if *imm >> shift << shift != *imm {
                        return Err(Error::InvalidImmediate(i.clone()));
                    }
                    if *imm >> shift >= 0x1000 {
                        return Err(Error::InvalidImmediate(i.clone()));
                    }

                    let opcode = opcode
                        | ((*imm >> shift) as u32) << 10
                        | ra.to_aarch64() << 5
                        | r.to_aarch64();
                    code.extend(opcode.to_le_bytes());
                }
                St(ty, r, ra, imm) => {
                    use Type::*;
                    let (shift, opcode) = match ty {
                        U8 => (0, 0x39000000),  // 00000039 	    strb w0, [x0, #0]
                        U16 => (1, 0x79000000), // 00000079 	    strh w0, [x0, #0]
                        U32 => (2, 0xB9000000), // 000000B9 	    str w0, [x0, #0]
                        U64 => (3, 0xF9000000), // 000000F9 	    str x0, [x0, #0]
                        S8 => (0, 0x39000000),  // 00000039 	    strb w0, [x0, #0]
                        S16 => (1, 0x79000000), // 00000079 	    strh w0, [x0, #0]
                        S32 => (2, 0xB9000000), // 000000B9 	    str w0, [x0, #0]
                        S64 => (3, 0xF9000000), // 000000F9 	    str x0, [x0, #0]
                        _ => return Err(Error::InvalidType(i.clone())),
                    };
                    if *imm >> shift << shift != *imm {
                        return Err(Error::InvalidImmediate(i.clone()));
                    }
                    if *imm >> shift >= 0x1000 {
                        return Err(Error::InvalidImmediate(i.clone()));
                    }
                    let opcode = opcode
                        | ((*imm >> shift) as u32) << 10
                        | ra.to_aarch64() << 5
                        | r.to_aarch64();
                    code.extend(opcode.to_le_bytes());
                }

                Vmov(..) | Vnot(..) | Vneg(..) | Vadd(..) | Vsub(..) | Vdiv(..)
                | Vand(..) | Vor(..) | Vxor(..) | Vld(..) | Vst(..) | Vshl(..)
                | Vshr(..) | Vmovi(..) | Vrecpe(..) | Vrsqrte(..) => vector::gen_vector_aarch64(&mut code, &i)?,

                D(ty, value) => {
                    match ty {
                        Type::U8 => code.extend([*value as u8]),
                        Type::U16 => code.extend((*value as u16).to_le_bytes()),
                        Type::U32 => code.extend((*value as u32).to_le_bytes()),
                        Type::U64 => code.extend((*value as u64).to_le_bytes()),
                        _ => return Err(Error::InvalidDataType(i.clone())),
                    }
                }

                _ => todo!("{i:?}"),

            }
        }
        for (loc, f) in fixups {
            match f {
                Fixup::Adr(dest, label) => {
                    // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions/ADR--Form-PC-relative-address-?lang=en
                    if let Some((_, offset)) = labels.iter().find(|(n, _)| *n == label) {
                        let delta = *offset as isize - loc as isize;
                        let opcode = 0x10000000_u32
                            | ((delta & 3) as u32) << 29
                            | ((delta >> 2 & 0x1fffff) as u32) * 32
                            | dest.to_aarch64();
                        code[loc..loc + 4].copy_from_slice(&opcode.to_le_bytes());
                    } else {
                        return Err(Error::MissingLabel(label));
                    }
                }
                Fixup::B(cond, label) => {
                    // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions/B-cond--Branch-conditionally-?lang=en
                    if let Some((_, offset)) = labels.iter().find(|(n, _)| *n == label) {
                        let delta = *offset as isize - loc as isize;
                        if (delta & 3) != 0 {
                            return Err(Error::BranchNotMod4(label));
                        }
                        if delta < -(1 << 19 + 2 - 1) || delta >= (1 << 19 + 2 - 1) {
                            return Err(Error::BranchOutOfRange(label));
                        }
                        let opcode = match cond {
                            // Cond::Always => 0x5400000e,
                            Cond::Eq => 0x54000000,
                            Cond::Ne => 0x54000001,
                            Cond::Sgt => 0x5400000c,
                            Cond::Sge => 0x5400000a,
                            Cond::Slt => 0x5400000b,
                            Cond::Sle => 0x5400000d,
                            Cond::Ugt => 0x54000008,
                            Cond::Uge => 0x54000002,
                            Cond::Ult => 0x54000003,
                            Cond::Ule => 0x54000009,
                        } | ((delta >> 1) & 0xfffff) as u32 * 16;
                        code[loc..loc + 4].copy_from_slice(&opcode.to_le_bytes());
                    } else {
                        return Err(Error::MissingLabel(label));
                    }
                }
                Fixup::J(label) => {
                    // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions/B-cond--Branch-conditionally-?lang=en
                    if let Some((_, offset)) = labels.iter().find(|(n, _)| *n == label) {
                        let delta = *offset as isize - loc as isize;
                        if (delta & 3) != 0 {
                            return Err(Error::BranchNotMod4(label));
                        }
                        if delta < -(1 << 26 + 2 - 1) || delta >= (1 << 26 + 2 - 1) {
                            return Err(Error::BranchOutOfRange(label));
                        }
                        let opcode = 0x14000000_u32 | ((delta >> 1) & 0x3ffffff) as u32;
                        code[loc..loc + 4].copy_from_slice(&opcode.to_le_bytes());
                    } else {
                        return Err(Error::MissingLabel(label));
                    }
                }
            }
        }
        Ok(Executable::new(&code, labels))
    }
}

fn adr_opcode(loc: usize, dest: R, offset: usize) -> u32 {
    let delta = offset as isize - loc as isize;
    let opcode = 0x10000000_u32
        | ((delta & 3) as u32) << 29
        | ((delta >> 2 & 0x1fffff) as u32) * 32
        | dest.to_aarch64();
    opcode
}

impl R {
    // Return the REX bit and the MODRM bits.
    pub fn to_aarch64(&self) -> u32 {
        self.0 as u32
    }
}

impl V {
    // Return the REX bit and the MODRM bits.
    pub fn to_aarch64(&self) -> u32 {
        self.0 as u32
    }
}

fn arith(code: &mut Vec<u8>, opcode: u32, dest: &R, src1: &R, src2: &R) {
    let coding = opcode | dest.to_aarch64() | src1.to_aarch64() << 5 | src2.to_aarch64() << 16;
    code.extend(coding.to_le_bytes());
}

fn movzkn(code: &mut Vec<u8>, opcode: u32, dest: &R, imm: u32, shift: u32) {
    let coding = opcode | dest.to_aarch64() | imm << 5 | shift << 21;
    code.extend(coding.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn basic() {
        use Ins::*;
        {
            // 46 0080 60000010 	    adr x0, l1
            // 47 0084 40000010 	    adr x0, l1
            // 48 0088 20000010 	    adr x0, l1
            // 49              	    l1:
            // 50 008c 00000010 	    adr x0, l1
            // 51 0090 E0FFFF10 	    adr x0, l1
            // 52 0094 C0FFFF10 	    adr x0, l1

            let prog = Executable::from_ir(&[
                // Imm(R(1), 123),
                Addr(R(0), 0),
                Addr(R(0), 0),
                Addr(R(0), 0),
                Label(0),
                Addr(R(0), 0),
                Addr(R(0), 0),
                Addr(R(0), 0),
                Ret,
            ])
            .unwrap();
            println!("{}", prog.fmt_32());
            assert_eq!(
                prog.fmt_32(),
                "60000010 40000010 20000010 00000010 e0ffff13 c0ffff13 c0035fd6"
            );
        }
        {
            // 103              	    # Always,
            // 104 0114 AE000054 	    b.al l4
            // 105              	    # Eq,
            // 106 0118 80000054 	    b.eq l4
            // 107              	    # Ne,
            // 108 011c 61000054 	    b.ne l4
            // 109              	    # Sgt,
            // 110 0120 4C000054 	    b.gt l4
            // 111              	    # Sge,
            // 112 0124 2A000054 	    b.ge l4
            // 113              	    # Slt,
            // 114              	    l4:
            // 115 0128 0B000054 	    b.lt l4
            // 116              	    # Sle,
            // 117 012c EDFFFF54 	    b.le l4
            // 118              	    # Ugt,
            // 119 0130 C8FFFF54 	    b.hi l4
            // 120              	    # Uge,
            // 121 0134 A2FFFF54 	    b.hs l4
            // 122              	    # Ult,
            // 123 0138 83FFFF54 	    b.lo l4
            // 124              	    # Ule,
            // 125 013c 69FFFF54 	    b.ls l4
            use Cond::*;
            let prog = Executable::from_ir(&[
                // Bcc(Always, 4),
                B(Eq, 4),
                B(Ne, 4),
                B(Sgt, 4),
                B(Sge, 4),
                Label(4),
                B(Slt, 4),
                B(Sle, 4),
                B(Ugt, 4),
                B(Uge, 4),
                B(Ult, 4),
                B(Ule, 4),
                Ret,
            ])
            .unwrap();
            println!("{}", prog.fmt_32());

            assert_eq!(prog.fmt_32(), "80000054 61000054 4c000054 2a000054 0b000054 edffff54 c8ffff54 a2ffff54 83ffff54 69ffff54 c0035fd6");
            // https://shell-storm.org/online/Online-Assembler-and-Disassembler/
        }
    }

    #[test]
    fn load_store() {
        use Ins::*;
        use Type::*;
        let prog = Executable::from_ir(&[
            Ld(U64, R(1), R(2), 0xabc * 8),
            Ld(U64, R(1), R(3), 0xabc * 8),
            Ld(U64, R(1), R(4), 0xabc * 8),
            Ld(U8, R(1), R(2), 0xabc * 1),
            Ld(U16, R(1), R(2), 0xabc * 2),
            Ld(U32, R(1), R(2), 0xabc * 4),
            Ld(U64, R(1), R(2), 0xabc * 8),
            Ld(S8, R(1), R(2), 0xabc * 1),
            Ld(S16, R(1), R(2), 0xabc * 2),
            Ld(S32, R(1), R(2), 0xabc * 4),
            Ld(S64, R(1), R(2), 0xabc * 8),
            St(U64, R(1), R(2), 0xabc * 8),
            St(U64, R(1), R(3), 0xabc * 8),
            St(U64, R(1), R(4), 0xabc * 8),
            St(U8, R(1), R(2), 0xabc * 1),
            St(U16, R(1), R(2), 0xabc * 2),
            St(U32, R(1), R(2), 0xabc * 4),
            St(U64, R(1), R(2), 0xabc * 8),
            St(S8, R(1), R(2), 0xabc * 1),
            St(S16, R(1), R(2), 0xabc * 2),
            St(S32, R(1), R(2), 0xabc * 4),
            St(S64, R(1), R(2), 0xabc * 8),
            Ret,
        ])
        .unwrap();
        println!("{}", prog.fmt_32());
        // https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=41f06af9+61f06af9+81f06af9+41f06a39+41f06a79+41f06ab9+41f06af9+41f0ea39+41f0ea79+41f0aab9+41f06af9+41f02af9+61f02af9+81f02af9+41f02a39+41f02a79+41f02ab9+41f02af9+41f02a39+41f02a79+41f02ab9+41f02af9+c0035fd6&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly
        assert_eq!(prog.fmt_32(), "41f06af9 61f06af9 81f06af9 41f06a39 41f06a79 41f06ab9 41f06af9 41f0ea39 41f0ea79 41f0aab9 41f06af9 41f02af9 61f02af9 81f02af9 41f02a39 41f02a79 41f02ab9 41f02af9 41f02a39 41f02a79 41f02ab9 41f02af9 c0035fd6");
    }

    #[test]
    fn enter_leave() {
        use Ins::*;
        use Type::*;
        let prog = Executable::from_ir(&[Enter(128), Leave(128), Ret]).unwrap();
        println!("{}", prog.fmt_32());
        // https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=ff0302d1+ff030291+c0035fd6&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly
        assert_eq!(prog.fmt_32(), "ff0302d1 ff030291 c0035fd6");
    }

    #[test]
    fn vmov() {
        use Ins::*;
        use Type::*;
        use Vsize::*;
        let prog = Executable::from_ir(&[Vmov(F32, V32, V(1), V(2))]).unwrap();
        println!("{}", prog.fmt_url());
        // https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=ff0302d1+ff030291+c0035fd6&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly
        assert_eq!(prog.fmt_32(), "4140201e");
    }

    #[test]
    fn vnot() {
        use Ins::*;
        use Type::*;
        use Vsize::*;
        let prog = Executable::from_ir(&[Vnot(U8, V64, V(1), V(2)), Vnot(U8, V128, V(1), V(2)), Ret]).unwrap();
        println!("{}", prog.fmt_url());
        // https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=ff0302d1+ff030291+c0035fd6&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly
        assert_eq!(prog.fmt_32(), "4158202e 4158206e c0035fd6");
    }
    #[test]
    fn vneg() {
        use Ins::*;
        use Type::*;
        use Vsize::*;
        let prog = Executable::from_ir(&[
            Vneg(U8, V64, V(1), V(2)),
            Vneg(U16, V64, V(1), V(2)),
            Vneg(U32, V64, V(1), V(2)),
            Vneg(U64, V64, V(1), V(2)),
            Vneg(U8, V128, V(1), V(2)),
            Vneg(U16, V128, V(1), V(2)),
            Vneg(U32, V128, V(1), V(2)),
            Vneg(U64, V128, V(1), V(2)),
            Ret
        ]).unwrap();
        println!("{}", prog.fmt_url());
        // https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=41b8202e+41b8602e+41b8a02e+41b8e07e+41b8206e+41b8606e+41b8a06e+41b8e06e+c0035fd6&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly
        assert_eq!(prog.fmt_32(), "41b8202e 41b8602e 41b8a02e 41b8e07e 41b8206e 41b8606e 41b8a06e 41b8e06e c0035fd6");
    }

    #[test]
    fn ins_size() {
        assert_eq!(std::mem::size_of::<Ins>(), 16);
    }

}

fn gen2(code: &mut Vec<u8>, opcode: u32, dest: &R, src: &R, i: &Ins) -> Result<(), Error> {
    let opcode = opcode & !(0x1f<<5 | 0x1f);
    let opcode = opcode
        | src.to_aarch64() << 5
        | dest.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}

fn gen3(code: &mut Vec<u8>, opcode: u32, dest: &R, src1: &R, src2: &R, i: &Ins) -> Result<(), Error> {
    let opcode = opcode & !(0x1f<<16 | 0x1f<<5 | 0x1f);
    let opcode = opcode
        | src2.to_aarch64() << 16
        | src1.to_aarch64() << 5
        | dest.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}

fn gen_mov(code: &mut Vec<u8>, opcode: u32, dest: &R, src: &R, i: &Ins) -> Result<(), Error> {
    // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions/MOV--register---Move-register-value--an-alias-of-ORR--shifted-register--?lang=en
    let opcode = opcode & !(0x1f << 16 | 0x1f);
    let opcode = opcode
        | dest.to_aarch64() << 16
        | dest.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}

fn gen_movi(code: &mut Vec<u8>, opcode: u32, dest: &R, imm: &u64, i: &Ins) -> Result<(), Error> {
    // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions/MOVZ--Move-wide-with-zero-?lang=en
    if *imm >= 0x10000 {
        return Err(Error::InvalidImmediate(i.clone()));
    }
    let opcode = opcode & !(0xffff << 5 | 0x1f);
    let opcode = opcode
        | (*imm << 5) as u32
        | dest.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}

fn gen_cmp(code: &mut Vec<u8>, opcode: u32, dest: &R, src: &R, i: &Ins) -> Result<(), Error> {
    // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions/CMP--extended-register---Compare--extended-register---an-alias-of-SUBS--extended-register--?lang=en
    let opcode = opcode & !(0x1f << 5 | 0x1f);
    let opcode = opcode
        | dest.to_aarch64() << 5
        | dest.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}

fn gen_cmpi(code: &mut Vec<u8>, opcode: u32, dest: &R, imm: &u64, i: &Ins) -> Result<(), Error> {
    // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions/CMP--immediate---Compare--immediate---an-alias-of-SUBS--immediate--?lang=en
    if *imm >= 0x1000 {
        return Err(Error::InvalidImmediate(i.clone()));
    }
    let opcode = opcode & !(0xfff << 5 | 0x1f);
    let opcode = opcode
        | (*imm << 5) as u32
        | dest.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}

fn gen_ldst(code: &mut Vec<u8>, opcode: u32, ty: Type, dest: &R, ra: &R, imm: &i32, i: &Ins) -> Result<(), Error> {
    let opcode = opcode & !(0x1f<<5 | 0x1f);
    let opcode = opcode
        | ra.to_aarch64() << 5
        | dest.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}

fn vgen2(code: &mut Vec<u8>, opcode: u32, dest: &V, src: &V, i: &Ins) -> Result<(), Error> {
    let opcode = opcode & !(0x1f<<5 | 0x1f);
    let opcode = opcode
        | src.to_aarch64() << 5
        | dest.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}

fn vgen3(code: &mut Vec<u8>, opcode: u32, dest: &V, src1: &V, src2: &V, i: &Ins) -> Result<(), Error> {
    let opcode = opcode & !(0x1f<<16 | 0x1f<<5 | 0x1f);
    let opcode = opcode
        | src2.to_aarch64() << 16
        | src1.to_aarch64() << 5
        | dest.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}

fn vgenmem(code: &mut Vec<u8>, opcode: u32, v: &V, r: &R, imm: &i32, i: &Ins) -> Result<(), Error> {
    let opcode = opcode & !(0xfff<<10 | 0x1f<<5 | 0x1f);
    if *imm >= (1<<12-1) || *imm < -(1<<12-1) {
        return Err(Error::InvalidImmediate(i.clone()));        
    }
    let opcode = opcode
        | ((imm & 0xfff) as u32) << 10
        | r.to_aarch64() << 5
        | v.to_aarch64();
    code.extend(opcode.to_le_bytes());
    Ok(())
}
