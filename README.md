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
