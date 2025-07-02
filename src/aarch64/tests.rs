use crate::{x86_64::cpu_info, Cond, Executable, Ins};

use super::{bitconst, regs, Aarch64Compiler};

#[test]
fn test_binary() {
    use regs::*;
    use Ins::*;
    let cpu_info = cpu_info(crate::CpuLevel::Simd512);
    let compiler = Aarch64Compiler::new(cpu_info);
    let prog = Executable::from_ir(
        compiler,
        &[
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
        ],
    )
    .unwrap();
    assert_eq!(
        prog.fmt_arm_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=410003ab+410003eb+410003ba+410003fa+410003ea+410003aa+410003ca+4120c39a+4124c39a+4128c39a+417c039b+4108c39a+410cc39a+410000b1+410000f1+41001fba+41001ffa+41001fea+41001faa+41001fca+4120df9a+4124df9a+4128df9a+417c1f9b+4108df9a+410cdf9a+418c04b1+418c04f1+08030058+410008ba+c8020058+410008fa+88020058+410008ea+48020058+410008aa+08020058+410008ca+c8010058+4120c89a+88010058+4124c89a+48010058+4128c89a+08010058+417c089b+c8000058+4108c89a+88000058+410cc89a+418c44b1+418c44f1+23010000+00000000&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_unary() {
    use regs::*;
    use Ins::*;
    let cpu_info = cpu_info(crate::CpuLevel::Simd512);
    let compiler = Aarch64Compiler::new(cpu_info);
    let prog = Executable::from_ir(
        compiler,
        &[
            Mov(X1, X2.into()),
            Not(X1, X2.into()),
            Neg(X1, X2.into()),
            Cmp(X1, X2.into()),
            Mov(X1, 123.into()),
            Not(X1, 123.into()),
            Neg(X1, 123.into()),
            Cmp(X1, 123.into()),
        ],
    )
    .unwrap();
    assert_eq!(
        prog.fmt_arm_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=e10302aa+e10322aa+e10302cb+3f0002eb+a1000058+c1000058+e1000058+48000058+3f0008eb+7b000000+00000000+84ffffff+ffffffff+85ffffff+ffffffff&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}

#[test]
fn test_misc() {
    use regs::*;
    use Cond::*;
    use Ins::*;
    let cpu_info = cpu_info(crate::CpuLevel::Simd512);
    let compiler = Aarch64Compiler::new(cpu_info);
    let prog = Executable::from_ir(
        compiler,
        &[
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
        ],
    )
    .unwrap();
    assert_eq!(
        prog.fmt_arm_url(),
        "https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=41000010+21000010+01000010+e1ffff10+20003fd6+20001fd6+02000014+01000014+00000014+ffffff17+a0000054+81000054+6c000054+4a000054+2b000054+0d000054+e8ffff54+c2ffff54+a3ffff54+89ffff54&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly"
    );
}
