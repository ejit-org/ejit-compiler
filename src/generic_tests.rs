//! Machine independent tests
//! 
//! TODO: Extend these to cover every instruction and register permutation.
//! 
use std::{cell::RefCell, sync::{Arc, Mutex}};

#[cfg(target_arch="x64_64")]
use crate::x86_64::cpu_info;

#[cfg(target_arch="aarch64")]
use crate::aarch64::cpu_info;

use super::*;


#[test]
fn instruction_size() {
    assert!(std::mem::size_of::<Ins>() <= 32);
}

#[test]
fn generic_basic() {
    use Ins::*;
    // use regs::*;
    let cpu_info = cpu_info();
    let res0 = cpu_info.res()[0];
    let arg0 = cpu_info.args()[0];
    let arg1 = cpu_info.args()[1];

    {
        let prog = Executable::from_ir(&[Mov(res0, 123.into()), Ret]).unwrap();
        let (res, _) = unsafe { prog.call(0, &[]).unwrap() };
        assert_eq!(res, 123);
    }
    {
        let prog = Executable::from_ir(&[Add(res0, arg0, arg1.into()),Ret,]).unwrap();
        let (res, _) = unsafe { prog.call(0, &[100, 1]).unwrap() };
        assert_eq!(res, 101);
    }
    {
        let prog = Executable::from_ir(&[Sub(res0, arg0, arg1.into()),Ret,]).unwrap();
        let (res, _) = unsafe { prog.call(0, &[100, 1]).unwrap() };
        assert_eq!(res, 99);
    }
}

#[test]
fn generic_branch() {
    fn test_one_branch(c: Cond, expected: [bool; 5]) {
        use Ins::*;
        use regs::*;
        const IS_FALSE : u32 = 0;
        const IS_TRUE : u32 = 1;
        let cpu_info = cpu_info();
        let res0 = cpu_info.res()[0];
        let arg0 = cpu_info.args()[0];
        let arg1 = cpu_info.args()[1];
        let mut prog = Executable::from_ir(&[
            Cmp(arg0, arg1.into()),
            Br(c, IS_TRUE),

            Label(IS_FALSE),
            Mov(res0, 0.into()),
            Ret,

            Label(IS_TRUE),
            Mov(res0, 1.into()),
            Ret,
        ])
        .unwrap();

        let tv = [[1, 1], [1, 2], [2, 1], [1, !0], [!0, 1]];
        let res = tv.iter().map(|args| unsafe { prog.call(0, &args[..]).unwrap().0 != 0 }).collect::<Vec<_>>();
        // println!("{res:?}");
        assert_eq!(&expected[..], &res, "{:?}", c);
    }

    use Cond::*;
    // test_one_branch(Always, [true, true, true, true, true]);
    test_one_branch(Eq, [true, false, false, false, false]);
    test_one_branch(Ne, [false, true, true, true, true]);
    test_one_branch(Sgt, [false, false, true, true, false]);
    test_one_branch(Sge, [true, false, true, true, false]);
    test_one_branch(Slt, [false, true, false, false, true]);
    test_one_branch(Sle, [true, true, false, false, true]);
    test_one_branch(Ugt, [false, false, true, false, true]);
    test_one_branch(Uge, [true, false, true, false, true]);
    test_one_branch(Ult, [false, true, false, true, false]);
    test_one_branch(Ule, [true, true, false, true, false]);
}

#[test]
fn generic_loop() {
    for _ in 0..3 {
        use Ins::*;
        use regs::*;
        let t0 = std::time::Instant::now();
        let cpu_info = cpu_info();
        let res0 = cpu_info.res()[0];
        let arg0 = cpu_info.args()[0];
        let arg1 = cpu_info.args()[1];
        const COUNT : R = R(0);
        const TOT : R = R(1);
        const LOOP : u32 = 0;
        let mut prog = Executable::from_ir(&[
            Mov(COUNT, 10000.into()),
            Mov(TOT, 0.into()),
            Label(LOOP),
            Add(TOT, TOT, COUNT.into()),
            Sub(COUNT, COUNT, 1.into()),
            Cmp(COUNT, 0.into()),
            Br(Cond::Ne, LOOP),
            Mov(res0, TOT.into()),
            Ret,
        ])
        .unwrap();
        // Compile time varies from 9μs (hot) to 11.4μs (cold).
        println!("compile time {}ns", std::time::Instant::elapsed(&t0).as_nanos());
        let (res, _) = unsafe { prog.call(0, &[]).unwrap() };
        assert_eq!(res, 50005000);
    }
}

#[test]
fn generic_load_store() {
    use Ins::*;
    use Type::*;
    use regs::*;
    let cpu_info = cpu_info();
    let res0 = cpu_info.res()[0];
    let arg0 = cpu_info.args()[0];
    let arg1 = cpu_info.args()[1];
    let sp = cpu_info.sp();
    let mut prog = Executable::from_ir(&[
        Enter(16.into()),
        St(U8, arg0, sp, 6),
        St(U8, arg1, sp, 7),
        Ld(U16, res0, sp, 6),
        Leave(16.into()),
        Ret,
    ])
    .unwrap();
    let (res, _) = unsafe { prog.call(0, &[0x34, 0x12]).unwrap() };
    #[cfg(target_endian="little")]
    assert_eq!(res, 0x1234);
    #[cfg(target_endian="big")]
    assert_eq!(res, 0x3412);
}
#[test]
fn generic_regreg() {
    use Ins::*;
    use Type::*;
    use regs::*;
    let mut a = [100_i64, 200, 15, 4, 1, -1, -1, -1, 123, -12300, -12300];
    let mut b = [  1_i64,   1,  3, 9, 9, 1, 1, 1, 100, 100, 100];
    let expected = [
        a[0] + b[0],
        a[1] - b[1],
        a[2] & b[2],
        a[3] | b[3],
        a[4] ^ b[4],
        a[5].wrapping_shl(b[5] as u32),
        (a[6] as u64).wrapping_shr(b[6] as u32) as i64,
        a[7].wrapping_shr(b[7] as u32),
        a[8] * b[8],
        (a[9] as u64).wrapping_div(b[9] as u64) as i64,
        a[10].wrapping_div(b[10]),
    ];

    let cpu_info = cpu_info();
    let res0 = cpu_info.res()[0];
    let arg0 = cpu_info.args()[0];
    let arg1 = cpu_info.args()[1];
    let ra = cpu_info.scratch()[4];
    let rb = cpu_info.scratch()[5];
    let mut prog = Executable::from_ir(&[
        Ld(U64, ra, arg0, 0*8),
        Ld(U64, rb, arg1, 0*8),
        Add(ra, ra, rb.into()),
        St(U64, ra, arg0, 0*8),

        Ld(U64, ra, arg0, 1*8),
        Ld(U64, rb, arg1, 1*8),
        Sub(ra, ra, rb.into()),
        St(U64, ra, arg0, 1*8),

        Ld(U64, ra, arg0, 2*8),
        Ld(U64, rb, arg1, 2*8),
        And(ra, ra, rb.into()),
        St(U64, ra, arg0, 2*8),

        Ld(U64, ra, arg0, 3*8),
        Ld(U64, rb, arg1, 3*8),
        Or(ra, ra, rb.into()),
        St(U64, ra, arg0, 3*8),

        Ld(U64, ra, arg0, 4*8),
        Ld(U64, rb, arg1, 4*8),
        Xor(ra, ra, rb.into()),
        St(U64, ra, arg0, 4*8),

        Ld(U64, ra, arg0, 5*8),
        Ld(U64, rb, arg1, 5*8),
        Shl(ra, ra, rb.into()),
        St(U64, ra, arg0, 5*8),

        Ld(U64, ra, arg0, 6*8),
        Ld(U64, rb, arg1, 6*8),
        Shr(ra, ra, rb.into()),
        St(U64, ra, arg0, 6*8),

        Ld(U64, ra, arg0, 7*8),
        Ld(U64, rb, arg1, 7*8),
        Sar(ra, ra, rb.into()),
        St(U64, ra, arg0, 7*8),

        Ld(U64, ra, arg0, 8*8),
        Ld(U64, rb, arg1, 8*8),
        Mul(ra, ra, rb.into()),
        St(U64, ra, arg0, 8*8),

        Ld(U64, ra, arg0, 9*8),
        Ld(U64, rb, arg1, 9*8),
        Udiv(ra, ra, rb.into()),
        St(U64, ra, arg0, 9*8),

        Ld(U64, ra, arg0, 10*8),
        Ld(U64, rb, arg1, 10*8),
        Sdiv(ra, ra, rb.into()),
        St(U64, ra, arg0, 10*8),
        Ret,
    ])
    .unwrap();
    
    let a0 = a.as_ptr() as u64;
    let a1 = b.as_ptr() as u64;
    let (res, _) = unsafe { prog.call(0, &[a0, a1]).unwrap() };

    assert_eq!(a, expected);
}


#[test]
fn generic_regimm() {
    use Ins::*;
    use Type::*;
    use regs::*;
    let mut a = [100_i64, 200, 15, 4, 1, -1, -1, -1, 123, -12300, -12300];
    let mut b = [  1_i64,   1,  3, 9, 9, 1, 1, 1, 100, 100, 100];
    let expected = [
        a[0] + b[0],
        a[1] - b[1],
        a[2] & b[2],
        a[3] | b[3],
        a[4] ^ b[4],
        a[5].wrapping_shl(b[5] as u32),
        (a[6] as u64).wrapping_shr(b[6] as u32) as i64,
        a[7].wrapping_shr(b[7] as u32),
        a[8] * b[8],
        (a[9] as u64).wrapping_div(b[9] as u64) as i64,
        a[10].wrapping_div(b[10]),
    ];

    let cpu_info = cpu_info();
    let res0 = cpu_info.res()[0];
    let arg0 = cpu_info.args()[0];
    let arg1 = cpu_info.args()[1];
    let ra = cpu_info.scratch()[4];
    let mut prog = Executable::from_ir(&[
        Ld(U64, ra, arg0, 0*8),
        Add(ra, ra, b[0].into()),
        St(U64, ra, arg0, 0*8),

        Ld(U64, ra, arg0, 1*8),
        Sub(ra, ra, b[1].into()),
        St(U64, ra, arg0, 1*8),

        Ld(U64, ra, arg0, 2*8),
        And(ra, ra, b[2].into()),
        St(U64, ra, arg0, 2*8),

        Ld(U64, ra, arg0, 3*8),
        Or(ra, ra, b[3].into()),
        St(U64, ra, arg0, 3*8),

        Ld(U64, ra, arg0, 4*8),
        Xor(ra, ra, b[4].into()),
        St(U64, ra, arg0, 4*8),

        Ld(U64, ra, arg0, 5*8),
        Shl(ra, ra, b[5].into()),
        St(U64, ra, arg0, 5*8),

        Ld(U64, ra, arg0, 6*8),
        Shr(ra, ra, b[6].into()),
        St(U64, ra, arg0, 6*8),

        Ld(U64, ra, arg0, 7*8),
        Sar(ra, ra, b[7].into()),
        St(U64, ra, arg0, 7*8),

        Ld(U64, ra, arg0, 8*8),
        Mul(ra, ra, b[8].into()),
        St(U64, ra, arg0, 8*8),

        Ld(U64, ra, arg0, 9*8),
        Udiv(ra, ra, b[9].into()),
        St(U64, ra, arg0, 9*8),

        Ld(U64, ra, arg0, 10*8),
        Sdiv(ra, ra, b[10].into()),
        St(U64, ra, arg0, 10*8),
        Ret,
    ])
    .unwrap();
    
    // println!("{}", prog.fmt_url());
    let a0 = a.as_ptr() as u64;
    let a1 = b.as_ptr() as u64;
    let (res, _) = unsafe { prog.call(0, &[a0, a1]).unwrap() };

    assert_eq!(a, expected);
}

#[test]
fn generic_call0() {
    use Ins::*;
    use Type::*;
    use regs::*;

    fn hello_world() {
        println!("hello world!");
    }

    let cpu_info = cpu_info();
    let mut prog = Executable::from_ir(&[
        Enter(0.into()),
        Call((hello_world as fn(), src0(), src0(), src0()).into()),
        Leave(0.into()),
        Ret,
    ])
    .unwrap();
    let (res, _) = unsafe { prog.call(0, &[]).unwrap() };
    // todo!();
}

#[test]
fn alloc_save() {
    use Ins::*;
    use Type::*;
    use regs::*;

    fn hello_world(x: u64, y: u64) {
        println!("{x:x} {y:x}");
        let res = y as *mut String;
        unsafe { *res = format!("hello world! {x}"); }
    }

    let mut cpu_info = cpu_info();

    // allocate a register saved by hello_world()
    // this means we don't need to save it over the call, but we
    // do need to save it on entry.
    // Note: if we change this to alloc_scratch(), we will
    // save it in the function call instead.
    let arg_in = cpu_info.alloc_any().unwrap();
    while let Ok(arg0) = cpu_info.alloc_save() {
        let entry : Box<EntryInfo> = EntryInfo::new()
            .with_args(&[arg0])
            .boxed();
        let entry_info = EntryInfo::new()
            .with_args(&[arg_in])
            .boxed();
        let mut prog = Executable::from_ir(&[
            Enter(entry_info.clone()),
            Mov(arg0, 123.into()),
            Call((hello_world as fn(u64, u64), src2(arg0, arg_in), src0(), src1(arg_in)).into()),
            Call((hello_world as fn(u64, u64), src2(arg0, arg_in), src0(), src1(arg_in)).into()),
            Leave(entry_info),
            Ret,
        ])
        .unwrap();

        let mut res = String::new();
        let res_ptr = &mut res as * mut String as u64;

        unsafe { prog.call(0, &[res_ptr]) };
        // println!("{}", prog.fmt_url());
        assert_eq!(res, "hello world! 123");
    }
}

#[test]
fn alloc_scratch() {
    use Ins::*;
    use Type::*;
    use regs::*;

    fn hello_world(x: u64) {
        println!("hello world! {x}");
    }

    let mut cpu_info = cpu_info();

    // allocate a register not saved by hello_world()
    // This time we save the register over the call but don't
    // need to save on entry.
    while let Ok(arg0) = cpu_info.alloc_scratch() {
        let entry : Box<EntryInfo> = EntryInfo::new().boxed();
        let mut prog = Executable::from_ir(&[
            Enter(entry.clone()),
            Mov(arg0, 123.into()),
            Call((hello_world as fn(u64), src1(arg0), src0(), src1(arg0)).into()),
            Call((hello_world as fn(u64), src1(arg0), src0(), src1(arg0)).into()),
            Leave(entry),
            Ret,
        ])
        .unwrap();

        let (res, _) = unsafe { prog.call(0, &[]).unwrap() };

    }
    // println!("{}", prog.fmt_url());
    // todo!();
}
