# Ejit compiler

This is the core repo of ejit-org representing the very minimal ejit JIT compiler.

EJit is not LLVM. It doesn't have compile times in seconds and doesn't produce bad code
just to make it work, it doesn't call glibc to do a memcpy.

Instead EJit is a tool for seasoned machine code experts to generate code on-the-fly
in microseconds to a high standard.

* Ejit won't fix your mistakes
* Ejit will fail to compile if you ask it to do something the platform does not support.
* You must do your own register allocation
* You must know your calling conventions and ABIs
* You must know the underlying instruction sets

If you want someone to hold your hand, use C instead.

## Example

```Rust
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

```