use crate::{regs, Executable, Ins, Type, Vsize, V};

#[test]
fn test_add() {
    use regs::*;
    use Ins::*;
    let prog = Executable::from_ir(&[
        Add(RAX, RAX, RAX.into()),
        Add(RAX, RAX, RCX.into()),
        Add(RAX, RAX, RDX.into()),
        Add(RAX, RAX, RBX.into()),
        Add(RAX, RAX, RSP.into()),
        Add(RAX, RAX, RBP.into()),
        Add(RAX, RAX, RSI.into()),
        Add(RAX, RAX, RDI.into()),
        Add(RAX, RAX, R8.into()),
        Add(RAX, RAX, R9.into()),
        Add(RAX, RAX, R10.into()),
        Add(RAX, RAX, R11.into()),
        Add(RAX, RAX, R12.into()),
        Add(RAX, RAX, R13.into()),
        Add(RAX, RAX, R14.into()),
        Add(RAX, RAX, R15.into()),
        Add(RAX, RAX, RAX.into()),
        Add(RAX, RCX, RAX.into()),
        Add(RAX, RDX, RAX.into()),
        Add(RAX, RBX, RAX.into()),
        Add(RAX, RSP, RAX.into()),
        Add(RAX, RBP, RAX.into()),
        Add(RAX, RSI, RAX.into()),
        Add(RAX, RDI, RAX.into()),
        Add(RAX, R8, RAX.into()),
        Add(RAX, R9, RAX.into()),
        Add(RAX, R10, RAX.into()),
        Add(RAX, R11, RAX.into()),
        Add(RAX, R12, RAX.into()),
        Add(RAX, R13, RAX.into()),
        Add(RAX, R14, RAX.into()),
        Add(RAX, R15, RAX.into()),
        Add(RAX, RAX, RAX.into()),
        Add(RCX, RAX, RAX.into()),
        Add(RDX, RAX, RAX.into()),
        Add(RBX, RAX, RAX.into()),
        Add(RSP, RAX, RAX.into()),
        Add(RBP, RAX, RAX.into()),
        Add(RSI, RAX, RAX.into()),
        Add(RDI, RAX, RAX.into()),
        Add(R8, RAX, RAX.into()),
        Add(R9, RAX, RAX.into()),
        Add(R10, RAX, RAX.into()),
        Add(R11, RAX, RAX.into()),
        Add(R12, RAX, RAX.into()),
        Add(R13, RAX, RAX.into()),
        Add(R14, RAX, RAX.into()),
        Add(R15, RAX, RAX.into()),
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=48+01+c0+48+01+c8+48+01+d0+48+01+d8+48+01+e0+48+01+e8+48+01+f0+48+01+f8+4c+01+c0+4c+01+c8+4c+01+d0+4c+01+d8+4c+01+e0+4c+01+e8+4c+01+f0+4c+01+f8+48+01+c0+48+89+c8+48+01+c0+48+89+d0+48+01+c0+48+89+d8+48+01+c0+48+89+e0+48+01+c0+48+89+e8+48+01+c0+48+89+f0+48+01+c0+48+89+f8+48+01+c0+4c+89+c0+48+01+c0+4c+89+c8+48+01+c0+4c+89+d0+48+01+c0+4c+89+d8+48+01+c0+4c+89+e0+48+01+c0+4c+89+e8+48+01+c0+4c+89+f0+48+01+c0+4c+89+f8+48+01+c0+48+01+c0+48+89+c1+48+01+c1+48+89+c2+48+01+c2+48+89+c3+48+01+c3+48+89+c4+48+01+c4+48+89+c5+48+01+c5+48+89+c6+48+01+c6+48+89+c7+48+01+c7+49+89+c0+49+01+c0+49+89+c1+49+01+c1+49+89+c2+49+01+c2+49+89+c3+49+01+c3+49+89+c4+49+01+c4+49+89+c5+49+01+c5+49+89+c6+49+01+c6+49+89+c7+49+01+c7&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );

    // TODO: Add(RAX,RSP,RSP)
}

#[test]
fn test_binary_regs() {
    use regs::*;
    use Ins::*;
    let prog = Executable::from_ir(&[
        Sub(RAX, RAX, RAX.into()),
        Sub(RAX, RAX, RCX.into()),
        Sub(RAX, RAX, RDX.into()),
        Sub(RAX, RAX, RBX.into()),
        Sub(RAX, RAX, RSP.into()),
        Sub(RAX, RAX, RBP.into()),
        Sub(RAX, RAX, RSI.into()),
        Sub(RAX, RAX, RDI.into()),
        Sub(RAX, RAX, R8.into()),
        Sub(RAX, RAX, R9.into()),
        Sub(RAX, RAX, R10.into()),
        Sub(RAX, RAX, R11.into()),
        Sub(RAX, RAX, R12.into()),
        Sub(RAX, RAX, R13.into()),
        Sub(RAX, RAX, R14.into()),
        Sub(RAX, RAX, R15.into()),
        Sub(RAX, RAX, RAX.into()),
        Sub(RAX, RCX, RAX.into()),
        Sub(RAX, RDX, RAX.into()),
        Sub(RAX, RBX, RAX.into()),
        Sub(RAX, RSP, RAX.into()),
        Sub(RAX, RBP, RAX.into()),
        Sub(RAX, RSI, RAX.into()),
        Sub(RAX, RDI, RAX.into()),
        Sub(RAX, R8, RAX.into()),
        Sub(RAX, R9, RAX.into()),
        Sub(RAX, R10, RAX.into()),
        Sub(RAX, R11, RAX.into()),
        Sub(RAX, R12, RAX.into()),
        Sub(RAX, R13, RAX.into()),
        Sub(RAX, R14, RAX.into()),
        Sub(RAX, R15, RAX.into()),
        Sub(RAX, RAX, RAX.into()),
        Sub(RCX, RAX, RAX.into()),
        Sub(RDX, RAX, RAX.into()),
        Sub(RBX, RAX, RAX.into()),
        Sub(RSP, RAX, RAX.into()),
        Sub(RBP, RAX, RAX.into()),
        Sub(RSI, RAX, RAX.into()),
        Sub(RDI, RAX, RAX.into()),
        Sub(R8, RAX, RAX.into()),
        Sub(R9, RAX, RAX.into()),
        Sub(R10, RAX, RAX.into()),
        Sub(R11, RAX, RAX.into()),
        Sub(R12, RAX, RAX.into()),
        Sub(R13, RAX, RAX.into()),
        Sub(R14, RAX, RAX.into()),
        Sub(R15, RAX, RAX.into()),
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=48+29+c0+48+29+c8+48+29+d0+48+29+d8+48+29+e0+48+29+e8+48+29+f0+48+29+f8+4c+29+c0+4c+29+c8+4c+29+d0+4c+29+d8+4c+29+e0+4c+29+e8+4c+29+f0+4c+29+f8+48+29+c0+48+89+c8+48+29+c0+48+89+d0+48+29+c0+48+89+d8+48+29+c0+48+89+e0+48+29+c0+48+89+e8+48+29+c0+48+89+f0+48+29+c0+48+89+f8+48+29+c0+4c+89+c0+48+29+c0+4c+89+c8+48+29+c0+4c+89+d0+48+29+c0+4c+89+d8+48+29+c0+4c+89+e0+48+29+c0+4c+89+e8+48+29+c0+4c+89+f0+48+29+c0+4c+89+f8+48+29+c0+48+29+c0+48+89+c1+48+29+c1+48+89+c2+48+29+c2+48+89+c3+48+29+c3+48+89+c4+48+29+c4+48+89+c5+48+29+c5+48+89+c6+48+29+c6+48+89+c7+48+29+c7+49+89+c0+49+29+c0+49+89+c1+49+29+c1+49+89+c2+49+29+c2+49+89+c3+49+29+c3+49+89+c4+49+29+c4+49+89+c5+49+29+c5+49+89+c6+49+29+c6+49+89+c7+49+29+c7&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );

    // TODO: Add(RAX,RSP,RSP)
}

#[test]
fn test_shift_ecx() {
    // We need to save ECX if the dest is not ecx.
    use regs::*;
    use Ins::*;
    let prog = Executable::from_ir(&[
        Shl(RAX, RAX, RAX.into()),
        Shl(RAX, RAX, RCX.into()),
        Shl(RAX, RCX, RAX.into()),
        Shl(RAX, RCX, RCX.into()),
        Shl(RCX, RAX, RAX.into()),
        Shl(RCX, RAX, RCX.into()),
        Shl(RCX, RCX, RAX.into()),
        Shl(RCX, RCX, RCX.into()),
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=51+48+89+c1+48+d3+e0+59+51+48+d3+e0+59+51+48+89+c8+48+89+c1+48+d3+e0+59+51+48+89+c8+48+d3+e0+59+48+89+c1+48+89+c1+48+d3+e1+48+89+c1+48+d3+e1+48+89+c1+48+d3+e1+48+d3+e1&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );

    // TODO: Add(RAX,RSP,RSP)
}

#[test]
fn test_div_eax() {
    // We may need to save EAX, EDX
    use regs::*;
    use Ins::*;
    let prog = Executable::from_ir(&[
        Udiv(RBX, RBX, RBX.into()),
        Udiv(RBX, RBX, RAX.into()),
        Udiv(RBX, RAX, RBX.into()),
        Udiv(RBX, RAX, RAX.into()),
        Udiv(RAX, RBX, RBX.into()),
        Udiv(RAX, RBX, RAX.into()),
        Udiv(RAX, RAX, RBX.into()),
        Udiv(RDX, RDX, RDX.into()),
        Udiv(RBX, RBX, RBX.into()),
        Udiv(RBX, RBX, RDX.into()),
        Udiv(RBX, RDX, RBX.into()),
        Udiv(RBX, RDX, RDX.into()),
        Udiv(RDX, RBX, RBX.into()),
        Udiv(RDX, RBX, RDX.into()),
        Udiv(RDX, RDX, RBX.into()),
        Udiv(RDX, RDX, RDX.into()),
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=50+52+48+89+d8+48+c7+c2+00+00+00+00+48+f7+f3+48+89+c3+5a+58+50+52+50+48+89+d8+48+c7+c2+00+00+00+00+48+f7+34+24+48+89+c3+48+83+c4+08+5a+58+50+52+48+c7+c2+00+00+00+00+48+f7+f3+48+89+c3+5a+58+50+52+50+48+c7+c2+00+00+00+00+48+f7+34+24+48+89+c3+48+83+c4+08+5a+58+52+48+89+d8+48+c7+c2+00+00+00+00+48+f7+f3+5a+52+50+48+89+d8+48+c7+c2+00+00+00+00+48+f7+34+24+48+83+c4+08+5a+52+48+c7+c2+00+00+00+00+48+f7+f3+5a+50+52+48+89+d0+48+c7+c2+00+00+00+00+48+f7+34+24+48+89+c2+48+83+c4+08+58+50+52+48+89+d8+48+c7+c2+00+00+00+00+48+f7+f3+48+89+c3+5a+58+50+52+52+48+89+d8+48+c7+c2+00+00+00+00+48+f7+34+24+48+89+c3+48+83+c4+08+5a+58+50+52+48+89+d0+48+c7+c2+00+00+00+00+48+f7+f3+48+89+c3+5a+58+50+52+52+48+89+d0+48+c7+c2+00+00+00+00+48+f7+34+24+48+89+c3+48+83+c4+08+5a+58+50+48+89+d8+48+c7+c2+00+00+00+00+48+f7+f3+48+89+c2+58+50+52+48+89+d8+48+c7+c2+00+00+00+00+48+f7+34+24+48+89+c2+48+83+c4+08+58+50+48+89+d0+48+c7+c2+00+00+00+00+48+f7+f3+48+89+c2+58+50+52+48+89+d0+48+c7+c2+00+00+00+00+48+f7+34+24+48+89+c2+48+83+c4+08+58&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );

    // TODO: Add(RAX,RSP,RSP)
}

#[test]
fn test_shift_regs() {
    use regs::*;
    use Ins::*;
    let prog = Executable::from_ir(&[
        Shl(RAX, RAX, RAX.into()),
        Shl(RAX, RAX, RDI.into()),
        Shl(RAX, RAX, R15.into()),
        Shl(RAX, RDI, RAX.into()),
        Shl(RAX, R15, RAX.into()),
        Shl(RDI, RAX, RAX.into()),
        Shl(R15, RAX, RAX.into()),
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=51+48+89+c1+48+d3+e0+59+51+48+89+f9+48+d3+e0+59+51+4c+89+f9+48+d3+e0+59+51+48+89+f8+48+89+c1+48+d3+e0+59+51+4c+89+f8+48+89+c1+48+d3+e0+59+51+48+89+c7+48+89+c1+48+d3+e7+59+51+49+89+c7+48+89+c1+49+d3+e7+59&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );

    // TODO: Add(RAX,RSP,RSP)
}

#[test]
fn test_binary() {
    use regs::*;
    use Ins::*;
    let prog = Executable::from_ir(&[
        Add(RAX, RAX, RAX.into()),
        Sub(RAX, RAX, RAX.into()),
        And(RAX, RAX, RAX.into()),
        Or(RAX, RAX, RAX.into()),
        Xor(RAX, RAX, RAX.into()),
        Shl(RAX, RAX, RAX.into()),
        Shr(RAX, RAX, RAX.into()),
        Sar(RAX, RAX, RAX.into()),
        Mul(RAX, RAX, RAX.into()),
        Udiv(RAX, RAX, RAX.into()),
        Sdiv(RAX, RAX, RAX.into()),
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=48+01+c0+48+29+c0+48+21+c0+48+09+c0+48+31+c0+51+48+89+c1+48+d3+e0+59+51+48+89+c1+48+d3+e8+59+51+48+89+c1+48+d3+f8+59+48+0f+af+c0+52+50+48+c7+c2+00+00+00+00+48+f7+34+24+48+83+c4+08+5a+52+50+48+99+48+f7+3c+24+48+83+c4+08+5a&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );

    // TODO: Add(RAX,RSP,RSP)
}

#[test]
fn test_vld() {
    use regs::*;
    use Ins::*;
    let prog = Executable::from_ir(&[
        Vld(Type::S8, Vsize::V128, V(0), RAX, 0),
        Vld(Type::S8, Vsize::V128, V(0), RCX, 0),
        Vld(Type::S8, Vsize::V128, V(1), RAX, 0),
        Vld(Type::S8, Vsize::V128, V(0), R8, 0),
        Vld(Type::S8, Vsize::V128, V(8), RAX, 0),
        Vld(Type::S8, Vsize::V128, V(9), R10, 0),
        Vld(Type::S8, Vsize::V256, V(0), RAX, 0),
        Vld(Type::S8, Vsize::V256, V(0), RCX, 0),
        Vld(Type::S8, Vsize::V256, V(1), RAX, 0),
        Vld(Type::S8, Vsize::V256, V(0), R8, 0),
        Vld(Type::S8, Vsize::V256, V(8), RAX, 0),
        Vld(Type::S8, Vsize::V256, V(9), R10, 0),
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+f8+10+80+00+00+00+00+c5+f8+10+81+00+00+00+00+c5+f8+10+88+00+00+00+00+c4+c1+78+10+80+00+00+00+00+c5+78+10+80+00+00+00+00+c4+41+78+10+8a+00+00+00+00+c5+fc+10+80+00+00+00+00+c5+fc+10+81+00+00+00+00+c5+fc+10+88+00+00+00+00+c4+c1+7c+10+80+00+00+00+00+c5+7c+10+80+00+00+00+00+c4+41+7c+10+8a+00+00+00+00&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_vst() {
    use regs::*;
    use Ins::*;
    let prog = Executable::from_ir(&[
        Vst(Type::S8, Vsize::V128, V(0), RAX, 0),
        Vst(Type::S8, Vsize::V128, V(0), RCX, 0),
        Vst(Type::S8, Vsize::V128, V(1), RAX, 0),
        Vst(Type::S8, Vsize::V128, V(0), R8, 0),
        Vst(Type::S8, Vsize::V128, V(8), RAX, 0),
        Vst(Type::S8, Vsize::V128, V(9), R10, 0),
        Vst(Type::S8, Vsize::V256, V(0), RAX, 0),
        Vst(Type::S8, Vsize::V256, V(0), RCX, 0),
        Vst(Type::S8, Vsize::V256, V(1), RAX, 0),
        Vst(Type::S8, Vsize::V256, V(0), R8, 0),
        Vst(Type::S8, Vsize::V256, V(8), RAX, 0),
        Vst(Type::S8, Vsize::V256, V(9), R10, 0),
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+f8+11+80+00+00+00+00+c5+f8+11+81+00+00+00+00+c5+f8+11+88+00+00+00+00+c4+c1+78+11+80+00+00+00+00+c5+78+11+80+00+00+00+00+c4+41+78+11+8a+00+00+00+00+c5+fc+11+80+00+00+00+00+c5+fc+11+81+00+00+00+00+c5+fc+11+88+00+00+00+00+c4+c1+7c+11+80+00+00+00+00+c5+7c+11+80+00+00+00+00+c4+41+7c+11+8a+00+00+00+00&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_modrm() {
    use regs::*;
    use Ins::*;
    use Type::*;
    let mut prog = Executable::from_ir(&[
        St(U8, RAX, RAX, 0),
        St(U8, RAX, RSP, 0),
        St(U8, RAX, RBP, 0),
        St(U8, RAX, R12, 0),
        St(U8, RAX, R13, 0),
        St(U8, RAX, R15, 0),
        St(U8, RAX, RAX, 0),
        St(U8, RSP, RSP, 0),
        St(U8, RBP, RBP, 0),
        St(U8, R12, R12, 0),
        St(U8, R13, R13, 0),
        St(U8, R15, R15, 0),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=40+88+00+40+88+04+24+40+88+45+00+41+88+04+24+41+88+45+00+41+88+07+40+88+00+40+88+24+24+40+88+6d+00+45+88+24+24+45+88+6d+00+45+88+3f+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
    let mut prog = Executable::from_ir(&[
        St(U8, RAX, RAX, 1),
        St(U8, RAX, RSP, 1),
        St(U8, RAX, RBP, 1),
        St(U8, RAX, R12, 1),
        St(U8, RAX, R13, 1),
        St(U8, RAX, R15, 1),
        St(U8, RAX, RAX, 1),
        St(U8, RSP, RSP, 1),
        St(U8, RBP, RBP, 1),
        St(U8, R12, R12, 1),
        St(U8, R13, R13, 1),
        St(U8, R15, R15, 1),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=40+88+40+01+40+88+44+24+01+40+88+45+01+41+88+44+24+01+41+88+45+01+41+88+47+01+40+88+40+01+40+88+64+24+01+40+88+6d+01+45+88+64+24+01+45+88+6d+01+45+88+7f+01+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
    let mut prog = Executable::from_ir(&[
        St(U8, RAX, RAX, 128),
        St(U8, RAX, RSP, 128),
        St(U8, RAX, RBP, 128),
        St(U8, RAX, R12, 128),
        St(U8, RAX, R13, 128),
        St(U8, RAX, R15, 128),
        St(U8, RAX, RAX, 128),
        St(U8, RSP, RSP, 128),
        St(U8, RBP, RBP, 128),
        St(U8, R12, R12, 128),
        St(U8, R13, R13, 128),
        St(U8, R15, R15, 128),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=40+88+80+80+00+00+00+40+88+84+24+80+00+00+00+40+88+85+80+00+00+00+41+88+84+24+80+00+00+00+41+88+85+80+00+00+00+41+88+87+80+00+00+00+40+88+80+80+00+00+00+40+88+a4+24+80+00+00+00+40+88+ad+80+00+00+00+45+88+a4+24+80+00+00+00+45+88+ad+80+00+00+00+45+88+bf+80+00+00+00+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_stb() {
    use regs::*;
    use Ins::*;
    use Type::*;
    let mut prog = Executable::from_ir(&[
        St(U8, RAX, RAX, 0),
        St(U8, RAX, RSP, 0),
        St(U8, RAX, RBP, 0),
        St(U8, RAX, R12, 0),
        St(U8, RAX, R13, 0),
        St(U8, RAX, R15, 0),
        St(U8, RAX, RAX, 0),
        St(U8, RSP, RSP, 0),
        St(U8, RBP, RBP, 0),
        St(U8, R12, R12, 0),
        St(U8, R13, R13, 0),
        St(U8, R15, R15, 0),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=40+88+00+40+88+04+24+40+88+45+00+41+88+04+24+41+88+45+00+41+88+07+40+88+00+40+88+24+24+40+88+6d+00+45+88+24+24+45+88+6d+00+45+88+3f+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_stw() {
    use regs::*;
    use Ins::*;
    use Type::*;
    let mut prog = Executable::from_ir(&[
        St(U16, RAX, RAX, 0),
        St(U16, RAX, RSP, 0),
        St(U16, RAX, RBP, 0),
        St(U16, RAX, R12, 0),
        St(U16, RAX, R13, 0),
        St(U16, RAX, R15, 0),
        St(U16, RAX, RAX, 0),
        St(U16, RSP, RSP, 0),
        St(U16, RBP, RBP, 0),
        St(U16, R12, R12, 0),
        St(U16, R13, R13, 0),
        St(U16, R15, R15, 0),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=66+40+89+00+66+40+89+04+24+66+40+89+45+00+66+41+89+04+24+66+41+89+45+00+66+41+89+07+66+40+89+00+66+40+89+24+24+66+40+89+6d+00+66+45+89+24+24+66+45+89+6d+00+66+45+89+3f+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_std() {
    use regs::*;
    use Ins::*;
    use Type::*;
    let mut prog = Executable::from_ir(&[
        St(U32, RAX, RAX, 0),
        St(U32, RAX, RSP, 0),
        St(U32, RAX, RBP, 0),
        St(U32, RAX, R12, 0),
        St(U32, RAX, R13, 0),
        St(U32, RAX, R15, 0),
        St(U32, RAX, RAX, 0),
        St(U32, RSP, RSP, 0),
        St(U32, RBP, RBP, 0),
        St(U32, R12, R12, 0),
        St(U32, R13, R13, 0),
        St(U32, R15, R15, 0),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=40+89+00+40+89+04+24+40+89+45+00+41+89+04+24+41+89+45+00+41+89+07+40+89+00+40+89+24+24+40+89+6d+00+45+89+24+24+45+89+6d+00+45+89+3f+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_stq() {
    use regs::*;
    use Ins::*;
    use Type::*;
    let mut prog = Executable::from_ir(&[
        St(U64, RAX, RAX, 0),
        St(U64, RAX, RSP, 0),
        St(U64, RAX, RBP, 0),
        St(U64, RAX, R12, 0),
        St(U64, RAX, R13, 0),
        St(U64, RAX, R15, 0),
        St(U64, RAX, RAX, 0),
        St(U64, RSP, RSP, 0),
        St(U64, RBP, RBP, 0),
        St(U64, R12, R12, 0),
        St(U64, R13, R13, 0),
        St(U64, R15, R15, 0),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=48+89+00+48+89+04+24+48+89+45+00+49+89+04+24+49+89+45+00+49+89+07+48+89+00+48+89+24+24+48+89+6d+00+4d+89+24+24+4d+89+6d+00+4d+89+3f+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_ld() {
    use regs::*;
    use Ins::*;
    use Type::*;
    let mut prog = Executable::from_ir(&[
        Ld(U8, RCX, RSI, 0),
        Ld(U16, RCX, RSI, 0),
        Ld(U32, RCX, RSI, 0),
        Ld(U64, RCX, RAX, 0),
        Ld(S8, RCX, RSI, 0),
        Ld(S16, RCX, RSI, 0),
        Ld(S32, RCX, RSI, 0),
        Ld(S64, RCX, RAX, 0),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=48+0f+b6+0e+66+48+0f+b7+0e+40+8b+0e+48+8b+08+48+0f+be+0e+66+48+0f+bf+0e+48+63+0e+48+8b+08+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );

}

#[test]
fn test_vpadd() {
    use regs::*;
    use Ins::*;
    use Type::*;
    use Vsize::*;
    let mut prog = Executable::from_ir(&[
        Vadd(U8, V128, V(0), V(0), V(0).into()),
        Vadd(U16, V128, V(0), V(0), V(0).into()),
        Vadd(U32, V128, V(0), V(0), V(0).into()),
        Vadd(U64, V128, V(0), V(0), V(0).into()),
        Vadd(F32, V128, V(0), V(0), V(0).into()),
        Vadd(F64, V128, V(0), V(0), V(0).into()),
        Vadd(U8, V128, V(0), V(0), V(0).into()),
        Vadd(U8, V128, V(15), V(0), V(0).into()),
        Vadd(U8, V128, V(0), V(15), V(0).into()),
        Vadd(U8, V128, V(0), V(0), V(15).into()),
        Vadd(U8, V128, V(1), V(2), V(3).into()),
        Vadd(U8, V256, V(0), V(0), V(0).into()),
        Vadd(U8, V256, V(0), V(0), V(15).into()),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+f9+fc+c0+c5+f9+fd+c0+c5+f9+fe+c0+c5+f9+d4+c0+c5+f8+58+c0+c5+f9+58+c0+c5+f9+fc+c0+c5+79+fc+f8+c5+81+fc+c0+c4+c1+79+fc+c7+c5+e9+fc+cb+c5+fd+fc+c0+c4+c1+7d+fc+c7+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_vpaddi() {
    use regs::*;
    use Ins::*;
    use Type::*;
    use Vsize::*;
    let mut prog = Executable::from_ir(&[
        Vadd(U8, V128, V(1), V(15), 0x12.into()),
        Vadd(U16, V128, V(1), V(15), 0x1234.into()),
        Vadd(U32, V128, V(1), V(15), 0x12345678.into()),
        Vadd(U64, V128, V(1), V(15), 0x123456789abcdef0_i64.into()),
        Vadd(F32, V128, V(1), V(15), 1.0_f32.into()),
        Vadd(F64, V128, V(1), V(15), 1.0_f64.into()),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+f9+fc+0d+29+00+00+00+c5+f9+fd+0d+31+00+00+00+c5+f9+fe+0d+39+00+00+00+c5+f9+d4+0d+41+00+00+00+c5+f8+58+0d+49+00+00+00+c5+f9+58+0d+51+00+00+00+c3+12+12+12+12+12+12+12+12+12+12+12+12+12+12+12+12+34+12+34+12+34+12+34+12+34+12+34+12+34+12+34+12+78+56+34+12+78+56+34+12+78+56+34+12+78+56+34+12+f0+de+bc+9a+78+56+34+12+f0+de+bc+9a+78+56+34+12+00+00+80+3f+00+00+80+3f+00+00+80+3f+00+00+80+3f+00+00+00+00+00+00+f0+3f+00+00+00+00+00+00+f0+3f&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_vpsub() {
    use regs::*;
    use Ins::*;
    use Type::*;
    use Vsize::*;
    let mut prog = Executable::from_ir(&[
        Vsub(U8, V128, V(0), V(0), V(0).into()),
        Vsub(U16, V128, V(0), V(0), V(0).into()),
        Vsub(U32, V128, V(0), V(0), V(0).into()),
        Vsub(U64, V128, V(0), V(0), V(0).into()),
        Vsub(F32, V128, V(0), V(0), V(0).into()),
        Vsub(F64, V128, V(0), V(0), V(0).into()),
        Vsub(U8, V128, V(0), V(0), V(0).into()),
        Vsub(U8, V128, V(15), V(0), V(0).into()),
        Vsub(U8, V128, V(0), V(15), V(0).into()),
        Vsub(U8, V128, V(0), V(0), V(15).into()),
        Vsub(U8, V128, V(1), V(2), V(3).into()),
        Vsub(U8, V256, V(0), V(0), V(0).into()),
        Vsub(U8, V256, V(0), V(0), V(15).into()),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+f9+f8+c0+c5+f9+f9+c0+c5+f9+fa+c0+c5+f9+fb+c0+c5+f8+5c+c0+c5+f9+5c+c0+c5+f9+f8+c0+c5+79+f8+f8+c5+81+f8+c0+c4+c1+79+f8+c7+c5+e9+f8+cb+c5+fd+f8+c0+c4+c1+7d+f8+c7+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_vandorxor() {
    use regs::*;
    use Ins::*;
    use Type::*;
    use Vsize::*;
    let mut prog = Executable::from_ir(&[
        Vand(U8, V128, V(1), V(2), V(3).into()),
        Vor(U8, V128, V(1), V(2), V(3).into()),
        Vxor(U8, V128, V(1), V(2), V(3).into()),
        Vand(U8, V256, V(1), V(2), V(3).into()),
        Vor(U8, V256, V(1), V(2), V(3).into()),
        Vxor(U8, V256, V(1), V(2), V(3).into()),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+e9+db+cb+c5+e9+eb+cb+c5+e9+ef+cb+c5+ed+db+cb+c5+ed+eb+cb+c5+ed+ef+cb+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_vshift() {
    use regs::*;
    use Ins::*;
    use Type::*;
    use Vsize::*;
    let mut prog = Executable::from_ir(&[
        Vshl(U32, V128, V(1), V(2), V(3).into()),
        Vshr(S32, V128, V(1), V(2), V(3).into()),
        Vshr(U32, V128, V(1), V(2), V(3).into()),
        Vshl(U32, V256, V(1), V(2), V(3).into()),
        Vshr(S32, V256, V(1), V(2), V(3).into()),
        Vshr(U32, V256, V(1), V(2), V(3).into()),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+e9+f2+cb+c5+e9+e2+cb+c5+e9+d2+cb+c5+ed+f2+cb+c5+ed+e2+cb+c5+ed+d2+cb+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_vmul() {
    use regs::*;
    use Ins::*;
    use Type::*;
    use Vsize::*;
    let mut prog = Executable::from_ir(&[
        Vmul(F32, V128, V(1), V(2), V(3).into()),
        Vmul(F64, V128, V(1), V(2), V(3).into()),
        Vmul(F32, V256, V(1), V(2), V(3).into()),
        Vmul(F64, V256, V(1), V(2), V(3).into()),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+e8+59+cb+c5+e9+59+cb+c5+ec+59+cb+c5+ed+59+cb+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_vmovi() {
    use regs::*;
    use Ins::*;
    use Type::*;
    use Vsize::*;
    let mut prog = Executable::from_ir(&[
        Vmov(U8, V128, V(15), 0x12.into()),
        Vmov(U16, V128, V(15), 0x1234.into()),
        Vmov(U32, V128, V(15), 0x12345678.into()),
        Vmov(U64, V128, V(15), 0x123456789abcdef0_i64.into()),
        Vmov(F32, V128, V(15), 1.0_f32.into()),
        Vmov(F64, V128, V(15), 1.0_f64.into()),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+f8+10+05+19+00+00+00+c5+f8+10+05+21+00+00+00+c5+f8+10+05+29+00+00+00+c5+f8+10+05+31+00+00+00+c3+12+12+12+12+12+12+12+12+12+12+12+12+12+12+12+12+34+12+34+12+34+12+34+12+34+12+34+12+34+12+34+12+78+56+34+12+78+56+34+12+78+56+34+12+78+56+34+12+f0+de+bc+9a+78+56+34+12+f0+de+bc+9a+78+56+34+12&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_vmov() {
    use regs::*;
    use Ins::*;
    use Type::*;
    use Vsize::*;
    let mut prog = Executable::from_ir(&[
        Vmov(U8, V128, V(0), V(0).into()),
        Vmov(U16, V128, V(0), V(0).into()),
        Vmov(U32, V128, V(0), V(0).into()),
        Vmov(U64, V128, V(0), V(0).into()),
        Vmov(U8, V128, V(1), V(2).into()),
        Vmov(U8, V128, V(2), V(4).into()),
        Vmov(U8, V128, V(3), V(6).into()),
        Vmov(U8, V128, V(4), V(8).into()),
        Vmov(U8, V128, V(5), V(10).into()),
        Ret,
    ])
    .unwrap();
    assert_eq!(
        prog.fmt_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=c5+f8+10+c0+c5+f8+10+c0+c5+f8+10+c0+c5+f8+10+c0+c5+f8+10+ca+c5+f8+10+d4+c5+f8+10+de+c4+c1+78+10+e0+c4+c1+78+10+ea+c3&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}
