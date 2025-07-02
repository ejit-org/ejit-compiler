#![allow(warnings)]
#![doc = include_str!("../README.md")]

use std::path::Display;
use std::rc::Rc;

use clear_cache::clear_cache;

pub type RInner = u16;

#[derive(Clone, Copy, Debug, PartialEq)]
/// Virtual 64 bit integer register
pub struct R(pub(crate) RInner);

impl R {
    fn rc(self, cpu_info: &CpuInfo) -> RegClass {
        cpu_info.ri(self).reg_class
    }
}

struct CompilerResult {
    pub code: Vec<u8>,
    pub labels: Vec<(u32, usize)>,
}

impl CompilerResult {
    fn new(code: Vec<u8>, labels: Vec<(u32, usize)>) -> Self {
        Self { code, labels }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Imm(pub u64);

#[derive(Clone, Debug, PartialEq)]
pub enum Src {
    SR(RInner),
    Imm(i64),
    Bytes(Box<[u8]>),
}

impl From<R> for Src {
    fn from(value: R) -> Self {
        Self::SR(value.0)
    }
}

impl From<&R> for Src {
    fn from(value: &R) -> Self {
        Self::SR(value.0)
    }
}

impl From<&[u8]> for Src {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(Box::from(value))
    }
}

macro_rules! from_t_for_src {
    ($($t : ty),*) => {
        $(
            impl From<$t> for Src {
                fn from(value: $t) -> Self {
                    Self::Imm(value.into())
                }
            }
        )*
    };
}

from_t_for_src!(u8, i8, u16, i16, u32, i32, i64);

impl From<u64> for Src {
    fn from(value: u64) -> Self {
        Self::Imm(i64::from_le_bytes(value.to_le_bytes()))
    }
}

impl From<usize> for Src {
    fn from(value: usize) -> Self {
        assert!(std::mem::size_of::<usize>() == 8);
        Self::Imm(i64::from_le_bytes(value.to_le_bytes()))
    }
}

impl From<isize> for Src {
    fn from(value: isize) -> Self {
        assert!(std::mem::size_of::<isize>() == 8);
        Self::Imm(i64::from_le_bytes(value.to_le_bytes()))
    }
}

impl From<f32> for Src {
    fn from(value: f32) -> Self {
        Self::from(value.to_bits())
    }
}

impl From<f64> for Src {
    fn from(value: f64) -> Self {
        Self::from(value.to_bits())
    }
}

impl Src {
    fn rc(&self, cpu_info: &CpuInfo) -> RegClass {
        match self {
            Src::SR(n) => R(*n).rc(cpu_info),
            _ => RegClass::Unknown,
        }
    }

    fn as_reg(&self) -> Option<R> {
        match self {
            Src::SR(n) => Some(R(*n)),
            _ => None,
        }
    }

    fn as_gpr(&self, cpu_info: &CpuInfo) -> Option<R> {
        match self {
            Src::SR(n) if R(*n).rc(cpu_info) == RegClass::GPR => Some(R(*n)),
            _ => None,
        }
    }

    fn as_vreg(&self, cpu_info: &CpuInfo) -> Option<R> {
        match self {
            Src::SR(n) if R(*n).rc(cpu_info) == RegClass::VREG => Some(R(*n)),
            _ => None,
        }
    }

    fn as_imm64(&self) -> Option<i64> {
        match self {
            Src::Imm(i) => Some(*i),
            _ => None,
        }
    }

    fn as_imm32(&self) -> Option<i32> {
        match self {
            Src::Imm(i) if TryInto::<i32>::try_into(*i).is_ok() => Some((*i).try_into().unwrap()),
            _ => None,
        }
    }
    fn as_imm8(&self) -> Option<i8> {
        match self {
            Src::Imm(i) if TryInto::<i8>::try_into(*i).is_ok() => Some((*i).try_into().unwrap()),
            _ => None,
        }
    }

    fn is_reg(&self) -> bool {
        match self {
            Src::SR(n) => true,
            _ => false,
        }
    }
    fn is_imm64(&self) -> bool {
        match self {
            Src::Imm(i) => true,
            _ => false,
        }
    }
    fn is_imm32(&self) -> bool {
        match self {
            Src::Imm(i) if TryInto::<i32>::try_into(*i).is_ok() => true,
            _ => false,
        }
    }
    fn is_imm8(&self) -> bool {
        match self {
            Src::Imm(i) if TryInto::<i8>::try_into(*i).is_ok() => true,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum Cond {
    Eq,
    Ne,
    Sgt,
    Sge,
    Slt,
    Sle,
    Ugt,
    Uge,
    Ult,
    Ule,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum Type {
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    S8,
    S16,
    S32,
    S64,
    S128,
    S256,
    F8,
    F16,
    F32,
    F64,
    F128,
    F256,
}

impl Type {
    fn bits(&self) -> usize {
        use Type::*;
        match self {
            U8 => 8,
            U16 => 16,
            U32 => 32,
            U64 => 64,
            U128 => 128,
            U256 => 256,
            S8 => 8,
            S16 => 16,
            S32 => 32,
            S64 => 64,
            S128 => 128,
            S256 => 256,
            F8 => 8,
            F16 => 16,
            F32 => 32,
            F64 => 64,
            F128 => 128,
            F256 => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
/// Vector size
pub enum Vsize {
    V8,
    V16,
    V32,
    V64,
    V128,
    V256,
    V512,
    V1024,
    V2048,
}

impl Vsize {
    fn bits(&self) -> usize {
        use Vsize::*;
        match self {
            V8 => 8,
            V16 => 16,
            V32 => 32,
            V64 => 64,
            V128 => 128,
            V256 => 256,
            V512 => 512,
            V1024 => 1024,
            V2048 => 2048,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
/// Vector size
enum Scale {
    X1,
    X2,
    X4,
    X8,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
/// Cpu level supported.
/// https://en.wikipedia.org/wiki/X86-64#Microarchitecture_levels
pub enum CpuLevel {
    /// Core features.
    /// x86-64-v1 mmx, sse, sse2
    /// Note: we do not support 64 bit SIMD.
    Scalar = 1,
    /// 128 bit SIMD.
    /// x86-64-v2 popcnt, sse3, sse4.1, sse4.2, ssse3
    /// aarch64: neon
    Simd128 = 2,
    /// 256 bit SIMD.
    /// x86-64-v3 avx, avx2, f16c, bmi1, bmi2, lzcnt, movbe
    /// aarch64: neon
    Simd256 = 3,
    /// 512 bit SIMD.
    /// x86-64-v4
    Simd512 = 4,
}

#[derive(Clone, Debug)]
pub struct RegInfo {
    pub reg_class: RegClass,
    pub callee_save: bool,
    pub scratch: bool,
    pub special: bool,
    pub arg: Option<usize>,
    pub ret: Option<usize>,
    pub name: &'static str,
}

impl RegInfo {
    pub const fn new(
        reg_class: RegClass,
        callee_save: bool,
        scratch: bool,
        special: bool,
        arg: Option<usize>,
        ret: Option<usize>,
        name: &'static str,
    ) -> Self {
        Self {
            reg_class,
            callee_save,
            scratch,
            special,
            arg,
            ret,
            name,
        }
    }
}

/// A desription of the CPU registers and their properties.
pub struct CpuInfo {
    cpu_level: CpuLevel,

    reg_info: &'static [RegInfo],

    alloc: [u128; 2],

    // Integer register class
    args: Box<[R]>,
    res: Box<[R]>,
    save: Box<[R]>,
    scratch: Box<[R]>,
    any: Box<[R]>,

    // Vector register class
    vargs: Box<[R]>,
    vres: Box<[R]>,
    vsave: Box<[R]>,
    vscratch: Box<[R]>,
    vany: Box<[R]>,

    sp: R,
}

impl CpuInfo {
    pub fn max_vbits(&self) -> usize {
        self.cpu_level.max_vbits()
    }

    pub fn cpu_level(&self) -> CpuLevel {
        self.cpu_level
    }

    pub fn ri(&self, r: R) -> &RegInfo {
        &self.reg_info[usize::from(r.0)]
    }

    pub fn args(&self) -> &[R] {
        &self.args
    }

    pub fn res(&self) -> &[R] {
        &self.res
    }

    pub fn save(&self) -> &[R] {
        &self.save
    }

    pub fn scratch(&self) -> &[R] {
        &self.scratch
    }

    pub fn vargs(&self) -> &[R] {
        &self.vargs
    }

    pub fn vres(&self) -> &[R] {
        &self.vres
    }

    pub fn vsave(&self) -> &[R] {
        &self.vsave
    }

    pub fn vscratch(&self) -> &[R] {
        &self.vscratch
    }

    pub fn sp(&self) -> R {
        self.sp
    }

    /// User integer register allocation.
    /// Registers allocated will be clobbered by calls.
    pub fn alloc_scratch(&mut self) -> Result<R, Error> {
        for R(i) in &self.scratch {
            let mask = 1 << (*i as u32);
            if self.alloc[0] & mask == 0 {
                self.alloc[0] |= mask;
                return Ok(R(*i));
            }
        }
        return Err(Error::NoAvailableRegisters);
    }

    /// User integer register allocation.
    /// Registers allocated will not be clobbered by calls.
    pub fn alloc_save(&mut self) -> Result<R, Error> {
        for R(i) in &self.save {
            let mask = 1 << (*i as u32);
            if self.alloc[0] & mask == 0 {
                self.alloc[0] |= mask;
                return Ok(R(*i));
            }
        }
        return Err(Error::NoAvailableRegisters);
    }

    /// User vector register allocation.
    /// Registers allocated will be clobbered by calls.
    pub fn alloc_vscratch(&mut self) -> Result<R, Error> {
        for R(i) in &self.vscratch {
            let mask = 1 << (*i as u32);
            if self.alloc[1] & mask == 0 {
                self.alloc[1] |= mask;
                return Ok(R(*i));
            }
        }
        return Err(Error::NoAvailableRegisters);
    }

    /// User integer register allocation.
    /// These registers *may* be clobbered by function calls, so save them!
    pub fn alloc_any(&mut self) -> Result<R, Error> {
        for R(i) in &self.any {
            let mask = 1 << (*i as u32);
            if self.alloc[0] & mask == 0 {
                self.alloc[0] |= mask;
                return Ok(R(*i));
            }
        }
        return Err(Error::NoAvailableRegisters);
    }

    /// User integer register allocation.
    /// These registers *may* be clobbered by function calls, so save them!
    pub fn alloc_vany(&mut self) -> Result<R, Error> {
        for R(i) in &self.vany {
            let mask = 1 << (*i as u32);
            if self.alloc[1] & mask == 0 {
                self.alloc[1] |= mask;
                return Ok(R(*i));
            }
        }
        return Err(Error::NoAvailableRegisters);
    }

    /// User integer register allocation.
    pub fn alloc_arg(&mut self) -> Result<R, Error> {
        for R(i) in &self.args {
            let mask = 1 << (*i as u32);
            if self.alloc[0] & mask == 0 {
                self.alloc[0] |= mask;
                return Ok(R(*i));
            }
        }
        return Err(Error::NoAvailableRegisters);
    }

    /// User integer register allocation.
    pub fn alloc_varg(&mut self) -> Result<R, Error> {
        for R(i) in &self.vargs {
            let mask = 1 << (*i as u32);
            if self.alloc[1] & mask == 0 {
                self.alloc[1] |= mask;
                return Ok(R(*i));
            }
        }
        return Err(Error::NoAvailableRegisters);
    }

    pub fn any(&self) -> &[R] {
        &self.any
    }

    pub fn vany(&self) -> &[R] {
        &self.vany
    }

    pub fn tmp_reg(&self, exclude: &[R]) -> Result<R, Error> {
        for r in &self.any {
            if exclude.contains(r) {
                return Ok(*r);
            }
        }
        Err(Error::CouldNotFindTempReg)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RegClass {
    GPR,
    VREG,
    FREG,
    MASK,
    Unknown,
}

pub fn src0() -> Box<[Src]> {
    Box::from(&[][..])
}

pub fn src1<T0: Into<Src>>(arg0: T0) -> Box<[Src]> {
    Box::from(&[arg0.into()][..])
}

pub fn src2<T0: Into<Src>, T1: Into<Src>>(arg0: T0, arg1: T1) -> Box<[Src]> {
    Box::from(&[arg0.into(), arg1.into()][..])
}

impl CpuLevel {
    fn max_vbits(&self) -> usize {
        match self {
            CpuLevel::Scalar => 64,
            CpuLevel::Simd128 => 128,
            CpuLevel::Simd256 => 256,
            CpuLevel::Simd512 => 512,
        }
    }
}


#[derive(Clone, Copy, Debug, PartialEq)]
enum LabelOrConst {
    Label(u32),
    Const(usize),
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// Patch up to four bytes of pc-relative instruction
struct PcRel {
    target: LabelOrConst,
    offset: usize,
    bits: u32,
    lshift: u32,
    rshift: u32,
    delta: isize,
}

#[derive(Clone, Copy, Debug, PartialEq)]
// TODO: make these more generic and pure.
// The parameter should only refer to the label or constant.
enum Fixup {
    // Adr(R, u32),
    // B(Cond, u32),
    // Const(usize, isize),
    // Label(u32, isize),

    PcRel(PcRel),
}

/// Common state for all CPU targets.
struct State {
    code: Vec<u8>,
    labels: Vec<(u32, usize)>,
    constants: Vec<u8>,
    fixups: Vec<(usize, Fixup)>,
    cpu_info: CpuInfo,
}

impl State {
    /// Append a constant to the constant pool.
    /// Returns the position of the constant in the pool.
    pub fn constant(&mut self, c: &[u8]) -> usize {
        if let Some(pos) = self.constants.windows(c.len()).position(|w| w == c) {
            pos
        } else {
            let pos = self.constants.len();
            self.constants.extend(c);
            pos
        }
    }

    /// Broadcast a constant value to a vector register, return the position of the constant in the constant pool.
    pub fn vector_constant(&mut self, ty: Type, vsize: Vsize, imm: i64, i: &Ins) -> Result<usize, Error> {
        if ty.bits() > vsize.bits() || ty.bits() > 64 {
            return Err(Error::InvalidType(i.clone()));
        }
        let elems = vsize.bits() / ty.bits();
        let mut c = vec![0_u8; vsize.bits() / 8];
        let esize = ty.bits() / 8;
        for e in 0..elems {
            c[e * esize..(e + 1) * esize].copy_from_slice(&imm.to_le_bytes()[0..esize]);
        }
        Ok(self.constant(&c))
    }

    /// Iterate over fixups, modifying the code.
    /// This is done after the code is generated so that forward refs can be resolved.
    pub fn do_fixups(&mut self, cbase: usize) -> Result<(), Error> {
        // TODO: make all fixups generic.
        for (loc, f) in &self.fixups {
            let loc = *loc;
            match f {
                // eg. sssss:imm19:00 => op | 00000:imm19:00000
                //     bits=19     rshift                 lshift
                Fixup::PcRel(PcRel {
                    target,
                    offset,
                    bits,
                    lshift,
                    rshift,
                    delta,
                }) => {
                    let offset = match target {
                        LabelOrConst::Label(label) => {
                            let Some((_, offset)) = self.labels.iter().find(|(n, _)| n == label) else {
                                return Err(Error::MissingLabel(*label));
                            };
                            *offset
                        }
                        LabelOrConst::Const(loc) => {
                            cbase + *loc
                        }
                    };

                    let delta = offset as isize - loc as isize - delta;
                    if delta < -(1 << bits - 1) || delta >= (1 << bits - 1) {
                        return Err(Error::InvalidOffset);
                    }
                    if (delta >> rshift << rshift) != delta {
                        return Err(Error::InvalidOffset);
                    }
                    let mask = if *bits >= 32 { !0 } else { (1 << *bits) - 1 };
                    let imm: u32 = ((delta >> rshift) & mask)
                        .try_into()
                        .map_err(|_| Error::InvalidOffset)?;
                    let original: u32 = u32::from_le_bytes(self.code[loc..loc + 4].try_into().unwrap());
                    let opcode = original | imm << lshift;
                    self.code[loc..loc + 4].copy_from_slice(&opcode.to_le_bytes());
                }
            }
        }
        Ok(())
    }

    /// Create a new compiler state.
    fn new(cpu_info: CpuInfo) -> Self {
        Self {
            code: Vec::new(),
            labels: Vec::new(),
            constants: Vec::new(),
            fixups: Vec::new(),
            cpu_info,
        }
    }

    /// Convert the state into a compiler result.
    fn into_compiler_result(&mut self) -> CompilerResult {
        CompilerResult::new(self.code.clone(), self.labels.clone())
    }

    /// Add a four byte instruction.
    fn push4(&mut self, value: u32) {
        self.code.extend_from_slice(&value.to_le_bytes());
    }

    /// Add a multi byte instruction.
    fn extend(&mut self, value: &[u8]) {
        self.code.extend_from_slice(value);
    }
}

/// A function entry including register saves
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EntryInfo {
    saves: Vec<R>,
    args: Vec<R>,
    res: Vec<R>,
    stack_size: usize,
}

impl EntryInfo {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_stack_size(self, stack_size: usize) -> Self {
        Self { stack_size, ..self }
    }

    pub fn with_saves(self, saves: &[R]) -> Self {
        Self {
            saves: saves.to_vec(),
            ..self
        }
    }

    pub fn with_args(self, args: &[R]) -> Self {
        Self {
            args: args.to_vec(),
            ..self
        }
    }

    pub fn with_res(self, res: &[R]) -> Self {
        Self {
            res: res.to_vec(),
            ..self
        }
    }

    pub fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

impl From<usize> for Box<EntryInfo> {
    fn from(stack_size: usize) -> Self {
        Box::new(EntryInfo {
            stack_size,
            ..Default::default()
        })
    }
}

/// A call to a function including args and scratch registers to be saved.
#[derive(Debug, Clone, PartialEq)]
pub struct CallInfo {
    ptr: u64,
    args: Box<[Src]>,
    res: Box<[Src]>,
    saves: Box<[Src]>,
}

macro_rules! from_fn {
    ($($t : ty , $na : expr , $nr : expr);*;) => {
        $(
            /// Call a function saving necessary volatile registers.
            impl From<($t, Box<[Src]>, Box<[Src]>, Box<[Src]>)> for Box<CallInfo> {
                fn from(value: ($t, Box<[Src]>, Box<[Src]>, Box<[Src]>)) -> Self {
                    let ptr = value.0 as usize as u64;
                    let args = value.1;
                    let res = value.2;
                    let saves = value.3;
                    Box::new(CallInfo {
                        ptr,
                        args,
                        res,
                        saves,
                    })
                }
            }

        )*

    };
}

from_fn!(
    fn() , 0, 0;
    fn(u64), 1, 0;
    fn(u64, u64), 1, 0;
    fn() -> u64 , 0, 1;
    fn(u64) -> u64, 1, 1;
    fn(u64, u64) -> u64, 1, 1;
);

#[derive(Clone, Debug, PartialEq)]
pub enum Ins {
    // Remember a PC-rel location.
    Label(u32),

    // Function entry & exit: Adjust sp by at least n bytes.
    Enter(Box<EntryInfo>),
    Leave(Box<EntryInfo>),

    // constants
    Addr(R, u32),

    // Mem
    Ld(Type, R, R, i32),
    St(Type, R, R, i32),
    Vld(Type, Vsize, R, R, i32),
    Vst(Type, Vsize, R, R, i32),

    // Integer Arithmetic.
    Add(R, R, Src),
    Sub(R, R, Src),
    Adc(R, R, Src),
    Sbb(R, R, Src),
    And(R, R, Src),
    Or(R, R, Src),
    Xor(R, R, Src),
    Shl(R, R, Src),
    Shr(R, R, Src),
    Sar(R, R, Src),
    Mul(R, R, Src),
    Udiv(R, R, Src),
    Sdiv(R, R, Src),

    Mov(R, Src),
    Cmp(R, Src),
    Not(R, Src),
    Neg(R, Src),
    Push(Src),
    Pop(Src),

    // Vector arithmetic
    Vadd(Type, Vsize, R, R, Src),
    Vsub(Type, Vsize, R, R, Src),
    Vand(Type, Vsize, R, R, Src),
    Vor(Type, Vsize, R, R, Src),
    Vxor(Type, Vsize, R, R, Src),
    Vshl(Type, Vsize, R, R, Src), // Note: on x86 src2 is broadcast.
    Vshr(Type, Vsize, R, R, Src), // Note: on x86 src2 is broadcast.
    Vmul(Type, Vsize, R, R, Src),

    Vmov(Type, Vsize, R, Src),
    Vrecpe(Type, Vsize, R, Src),
    Vrsqrte(Type, Vsize, R, Src),

    // Vcmp(Cond, Type, Vsize, R, Src),
    // Vsel(Type, Vsize, R, R, Src),
    // Vany(Type, Vsize, R, Src), // nz if any true
    // Vall(Type, Vsize, R, Src), // nz if all true

    // Control flow
    Call(Box<CallInfo>),
    CallLocal(u32),

    /// Call indirect using stack or R(30)
    Ci(R),

    /// Branch indirect
    Bi(R),

    /// Use the flags to branch conditionally
    /// Only after a Cmp
    Br(Cond, u32),
    Jmp(u32),

    Cmov(Cond, R, Src),

    /// Return using stack or R(30)
    Ret,

    /// Constant data.
    D(Type, u64),

    /// Multiple register move.
    Movm(Box<[R]>, Box<[R]>),
}

pub trait Compiler : Sized {
    /// Get the compiler state including the cpu info.
    fn state(&mut self) -> &mut State;

    /// Iterate over the instructions and compile them.
    fn compile(&mut self, ins: &[Ins]) -> Result<CompilerResult, Error> {
        // for i in ins {
        //     match i {
        //         Ins::Label(value) => self.label(*value, i)?,
        //         Ins::Enter(entry_info) => self.enter(entry_info, i)?,
        //         Ins::Leave(entry_info) => self.leave(entry_info, i)?,
        //         Ins::Addr(r, value) => self.addr(*r, *value, i)?,
        //         Ins::Ld(ty, r, r1, offset) => self.ld(*ty, *r, *r1, *offset, i)?,
        //         Ins::St(ty, r, r1, offset) => self.st(*ty, *r, *r1, *offset, i)?,
        //         Ins::Vld(ty, vsize, r, r1, offset) => self.vld(*ty, *vsize, *r, *r1, *offset, i)?,
        //         Ins::Vst(ty, vsize, r, r1, offset) => self.vst(*ty, *vsize, *r, *r1, *offset, i)?,
        //         Ins::Add(r, r1, src) => self.add(*r, *r1, src, i)?,
        //         Ins::Sub(r, r1, src) => self.sub(*r, *r1, src, i)?,
        //         Ins::Adc(r, r1, src) => self.adc(*r, *r1, src, i)?,
        //         Ins::Sbb(r, r1, src) => self.sbb(*r, *r1, src, i)?,
        //         Ins::And(r, r1, src) => self.and(*r, *r1, src, i)?,
        //         Ins::Or(r, r1, src) => self.or(*r, *r1, src, i)?,
        //         Ins::Xor(r, r1, src) => self.xor(*r, *r1, src, i)?,
        //         Ins::Shl(r, r1, src) => self.shl(*r, *r1, src, i)?,
        //         Ins::Shr(r, r1, src) => self.shr(*r, *r1, src, i)?,
        //         Ins::Sar(r, r1, src) => self.sar(*r, *r1, src, i)?,
        //         Ins::Mul(r, r1, src) => self.mul(*r, *r1, src, i)?,
        //         Ins::Udiv(r, r1, src) => self.udiv(*r, *r1, src, i)?,
        //         Ins::Sdiv(r, r1, src) => self.sdiv(*r, *r1, src, i)?,
        //         Ins::Mov(r, src) => self.mov(*r, src, i)?,
        //         Ins::Cmp(r, src) => self.cmp(*r, src, i)?,
        //         Ins::Not(r, src) => self.not(*r, src, i)?,
        //         Ins::Neg(r, src) => self.neg(*r, src, i)?,
        //         Ins::Push(src) => self.push(src, i)?,
        //         Ins::Pop(src) => self.pop(src, i)?,
        //         Ins::Vadd(ty, vsize, r, r1, src) => self.vadd(*ty, *vsize, *r, *r1, src, i)?,
        //         Ins::Vsub(ty, vsize, r, r1, src) => self.vsub(*ty, *vsize, *r, *r1, src, i)?,
        //         Ins::Vand(ty, vsize, r, r1, src) => self.vand(*ty, *vsize, *r, *r1, src, i)?,
        //         Ins::Vor(ty, vsize, r, r1, src) => self.vor(*ty, *vsize, *r, *r1, src, i)?,
        //         Ins::Vxor(ty, vsize, r, r1, src) => self.vxor(*ty, *vsize, *r, *r1, src, i)?,
        //         Ins::Vshl(ty, vsize, r, r1, src) => self.vshl(*ty, *vsize, *r, *r1, src, i)?,
        //         Ins::Vshr(ty, vsize, r, r1, src) => self.vshr(*ty, *vsize, *r, *r1, src, i)?,
        //         Ins::Vmul(ty, vsize, r, r1, src) => self.vmul(*ty, *vsize, *r, *r1, src, i)?,
        //         Ins::Vmov(ty, vsize, r, src) => self.vmov(*ty, *vsize, *r, src, i)?,
        //         Ins::Vrecpe(ty, vsize, r, src) => self.vrecpe(*ty, *vsize, *r, src, i)?,
        //         Ins::Vrsqrte(ty, vsize, r, src) => self.vrsqrte(*ty, *vsize, *r, src, i)?,
        //         Ins::Call(call_info) => self.call(call_info, i)?,
        //         Ins::CallLocal(value) => self.call_local(*value, i)?,
        //         Ins::Ci(r) => self.ci(*r, i)?,
        //         Ins::Bi(r) => self.bi(*r, i)?,
        //         Ins::Br(cond, value) => self.br(*cond, *value, i)?,
        //         Ins::Jmp(value) => self.jmp(*value, i)?,
        //         Ins::Cmov(cond, r, src) => self.cmov(*cond, *r, src, i)?,
        //         Ins::Ret => self.ret()?,
        //         Ins::D(ty, value) => self.d(*ty, *value, i)?,
        //         Ins::Movm(dest, src) => self.movm(dest, src, i)?,
        //     }
        // }
        let state = self.state();
        state.do_fixups(0)?;
        Ok(state.into_compiler_result())
    }

    // Remember a PC-rel location.
    fn label(&mut self, value: u32, i: &Ins) -> Result<(), Error> {
        let state = self.state();
        let loc = state.code.len();
        state.labels.push((value, loc));
        Ok(())
    }

    /// ABI-aware Function entry.
    fn enter(&mut self, entry_info: &EntryInfo, i: &Ins) -> Result<(), Error> {
        let scratch = entry_info.stack_size + 15 & !15;
        let saves = entry_info.saves.len() * 8 + 15 & !15;
        let spdiff = scratch + saves;
        let sp = self.state().cpu_info.sp();
        if spdiff != 0 {
            let imm = &spdiff.into();
            self.sub(sp, sp, imm, i)?;
        }

        for (idx, r) in entry_info.saves.iter().copied().enumerate() {
            self.st(Type::U64, r, sp, (scratch + idx * 8) as i32, i)?;
        }

        let args_src: Box<[R]> = self
            .state()
            .cpu_info
            .args()
            .iter()
            .take(entry_info.args.len())
            .cloned()
            .collect();
        self.movm(&entry_info.args, &args_src, i)?;

        Ok(())
    }

    /// ABI-aware Function exit.
    fn leave(&mut self, entry_info: &EntryInfo, i: &Ins) -> Result<(), Error> {
        let scratch = entry_info.stack_size + 15 & !15;
        let saves = entry_info.saves.len() * 8 + 15 & !15;
        let spdiff = scratch + saves;
        let sp = self.state().cpu_info.sp();
    
        let res_dest: Box<[R]> = self.state()
            .cpu_info
            .res()
            .iter()
            .take(entry_info.res.len())
            .cloned()
            .collect();
    
        self.movm(&res_dest, &entry_info.res, i)?;
    
        for (idx, r) in entry_info.saves.iter().copied().enumerate().rev() {
            self.ld(Type::U64, r, sp, (scratch + idx * 8) as i32, i)?;
        }

        if spdiff != 0 {
            let imm = &spdiff.into();
            self.add(sp, sp, imm, i)?;
        }

        Ok(())
    }

    // Constants
    fn addr(&mut self, reg: R, value: u32, i: &Ins) -> Result<(), Error>;

    /// Integer load.
    fn ld(&mut self, ty: Type, r: R, ra: R, offset: i32, i: &Ins) -> Result<(), Error>;

    /// Integer store
    fn st(&mut self, ty: Type, r: R, ra: R, offset: i32, i: &Ins) -> Result<(), Error>;

    /// Vector and FP load
    fn vld(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        offset: i32,
        i: &Ins,
    ) -> Result<(), Error>;

    /// Vector and FP store
    fn vst(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        offset: i32,
        i: &Ins,
    ) -> Result<(), Error>;

    // Integer Arithmetic
    fn add(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn sub(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn adc(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn sbb(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn and(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn or(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn xor(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn shl(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn shr(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn sar(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn mul(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn udiv(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn sdiv(&mut self, reg1: R, reg2: R, src: &Src, i: &Ins) -> Result<(), Error>;

    fn mov<S: Into<Src>>(&mut self, dest: R, src: S) -> Result<&mut Self, Error>;
    fn cmp(&mut self, reg: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn not(&mut self, reg: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn neg(&mut self, reg: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn push(&mut self, src: &Src, i: &Ins) -> Result<(), Error>;
    fn pop(&mut self, src: &Src, i: &Ins) -> Result<(), Error>;

    // Vector arithmetic
    fn vadd(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        src: &Src,
        i: &Ins,
    ) -> Result<(), Error>;
    fn vsub(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        src: &Src,
        i: &Ins,
    ) -> Result<(), Error>;
    fn vand(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        src: &Src,
        i: &Ins,
    ) -> Result<(), Error>;
    fn vor(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        src: &Src,
        i: &Ins,
    ) -> Result<(), Error>;
    fn vxor(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        src: &Src,
        i: &Ins,
    ) -> Result<(), Error>;
    fn vshl(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        src: &Src,
        i: &Ins,
    ) -> Result<(), Error>;
    fn vshr(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        src: &Src,
        i: &Ins,
    ) -> Result<(), Error>;
    fn vmul(
        &mut self,
        ty: Type,
        vsize: Vsize,
        reg1: R,
        reg2: R,
        src: &Src,
        i: &Ins,
    ) -> Result<(), Error>;

    fn vmov(&mut self, ty: Type, vsize: Vsize, reg: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn vrecpe(&mut self, ty: Type, vsize: Vsize, reg: R, src: &Src, i: &Ins) -> Result<(), Error>;
    fn vrsqrte(&mut self, ty: Type, vsize: Vsize, reg: R, src: &Src, i: &Ins) -> Result<(), Error>;

    /// ABI-aware call to a function.
    /// Saves necessary volatile registers and passes arguments in the correct registers.
    /// Returns the result in the correct register.
    fn call(&mut self, call_info: &CallInfo, i: &Ins) -> Result<(), Error> {
        // TODO: check this in all cases
        // TODO: handle fp and vector register classes.
        // TODO: make sure the stack is aligned.
        let sp = self.state().cpu_info.sp();
        for src in call_info.saves.iter() {
            self.push(src, i)?;
        }

        let mut num_iargs = 0;
        let mut num_vargs = 0;
        let mut bytes_pushed = 0;
        let mut srcs = Vec::new();
        let mut dests = Vec::new();
        let mut immsrcs = Vec::<i64>::new();
        let mut immdests = Vec::new();
        for arg in &call_info.args {
            if let Some(src) = arg.as_gpr(&self.state().cpu_info) {
                if let Some(dest) = self.state().cpu_info.args.get(num_iargs).cloned() {
                    srcs.push(src);
                    dests.push(dest);
                    num_iargs += 1;
                } else {
                    self.push(&arg, i)?;
                    bytes_pushed += 8;
                }
            }
            if let Some(imm) = arg.as_imm64() {
                if let Some(dest) = self.state().cpu_info.args.get(num_iargs).cloned() {
                    immsrcs.push(imm);
                    immdests.push(dest);
                    num_iargs += 1;
                } else {
                    self.push(&arg, i)?;
                    bytes_pushed += 8;
                }
            } else {
                return Err(Error::InvalidSrcArgument(i.clone()));
            }
        }

        // Copy register args.
        self.movm(&dests, &srcs, i)?;

        /// Copy immediate args.
        for (imm, dest) in immsrcs.into_iter().zip(immdests.into_iter()) {
            self.mov(dest, Src::from(imm))?;
        }

        // Call the function.
        self.call_abs(call_info.ptr as usize as u64, i)?;

        if bytes_pushed != 0 {
            self.add(sp, sp, &bytes_pushed.into(), i)?;
        }

        for src in call_info.saves.iter().rev() {
            self.pop(src, i)?;
        }
        Ok(())
    }

    /// Plain call to local label.
    fn call_local(&mut self, label: u32, i: &Ins) -> Result<(), Error>;

    /// Plain call to an absolute location.
    fn call_abs(&mut self, loc: u64, i: &Ins) -> Result<(), Error>;

    /// Call indirect using stack or R(30)
    fn ci(&mut self, reg: R, i: &Ins) -> Result<(), Error>;

    /// Branch indirect
    fn bi(&mut self, reg: R, i: &Ins) -> Result<(), Error>;

    /// Use the flags to branch conditionally
    /// Only after a Cmp
    fn br(&mut self, cond: Cond, value: u32, i: &Ins) -> Result<(), Error>;
    fn jmp(&mut self, value: u32, i: &Ins) -> Result<(), Error>;

    fn cmov(&mut self, cond: Cond, reg: R, src: &Src, i: &Ins) -> Result<(), Error>;

    /// Return using stack or R(30)
    fn ret(&mut self) -> Result<&mut Self, Error>;

    /// Constant data
    fn d(&mut self, ty: Type, value: u64, i: &Ins) -> Result<(), Error> {
        let code = &mut self.state().code;
        // TODO: check for overflow.
        match ty {
            Type::U8 => code.extend((value as u8).to_le_bytes()),
            Type::U16 => code.extend((value as u16).to_le_bytes()),
            Type::U32 => code.extend((value as u32).to_le_bytes()),
            Type::U64 => code.extend((value as u64).to_le_bytes()),
            _ => return Err(Error::InvalidDataType(i.clone())),
        }
        Ok(())
    }

    /// Move multiple. Move a set of registers into another set of registers.
    fn movm(&mut self, dest: &[R], src: &[R], i: &Ins) -> Result<(), Error> {
        if dest.len() != src.len() {
            return Err(Error::InvalidArgs);
        }
        let mut pops = Vec::new();
        for j in 0..dest.len() {
            let d = dest[j];
            let s = src[j];
            if d != s {
                if src[j + 1..].contains(&d) {
                    self.push(&s.into(), i)?;
                    pops.push(d);
                } else {
                    self.mov(d, s)?;
                }
            }
        }
        for d in pops.into_iter().rev() {
            self.pop(&d.into(), i)?;
        }
        Ok(())
    }

    fn to_executable(&mut self) -> Result<Executable, Error> {
        let state = self.state();
        state.do_fixups(0)?;
        let res = state.into_compiler_result();
        Executable::from_result(res)
    }
}

pub struct ErrorContext {
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    InvalidRegisterNumber(Ins),
    InvalidLabel,
    InvalidOffset,
    InvalidArgs,
    InvalidImmediate(Ins),
    MissingLabel(u32),
    BranchOutOfRange(u32),
    BranchNotMod4(u32),
    InvalidType(Ins),
    StackFrameMustBeModulo16(Ins),
    InvalidVectorSize(Ins),
    VectorOperationNotSupported(Ins),
    VectorSizeNotSupported(Ins),
    VectorTypeNotSupported(Ins),
    UnsupportedVectorOperation(Ins),
    UnsupportedBaseOperation(Ins),
    UnsupportedOperation(Ins),
    InvalidDataType(Ins),
    InvalidRegs(Ins),
    OffsetToLarge(u32),
    InvalidAddress(Ins),
    CodeTooBig,
    CpuLevelTooLow(Ins),
    InvalidSrcArgument(Ins),
    NoAvailableRegisters,
    CouldNotFindTempReg,
    BadBytesLength,
    BadRegClass(Ins),
    SpNotAllowed(Ins),

    BadRegClass2(&'static str, R),
    InvalidSrcArgument2(&'static str),
}

pub struct Executable {
    bytes: *const u8,
    len: usize,
    labels: Vec<(u32, usize)>,
}

impl Executable {
    fn from_ir<C: Compiler>(mut compiler: C, ins: &[Ins]) -> Result<Self, Error> {
        let res = compiler.compile(ins)?;
        Ok(Self::new(&res.code, res.labels))
    }

    fn from_result(res: CompilerResult) -> Result<Self, Error> {
        Ok(Self::new(&res.code, res.labels))
    }

    fn new(code: &[u8], labels: Vec<(u32, usize)>) -> Self {
        let addr = std::ptr::null_mut();
        let len = code.len();
        let fd = -1;
        let offset = 0;
        #[cfg(target_os = "macos")]
        unsafe {
            // https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-jit
            // Ian Hobson's Mac Jit runes.
            let prot = libc::PROT_EXEC | libc::PROT_READ | libc::PROT_WRITE;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT;
            let mem = libc::mmap(addr, len, prot, flags, fd, offset);

            libc::pthread_jit_write_protect_np(0);

            let slice = std::slice::from_raw_parts_mut(mem as *mut u8, len);
            slice.copy_from_slice(&code);

            libc::pthread_jit_write_protect_np(1);

            let bytes = mem as *const u8;
            clear_cache::clear_cache(bytes, bytes.offset(code.len() as isize));
            Self { bytes, len, labels }
        }
        #[cfg(target_os = "linux")]
        unsafe {
            let prot = libc::PROT_EXEC | libc::PROT_READ | libc::PROT_WRITE;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            let mem = libc::mmap(addr, len, prot, flags, fd, offset);
            let slice = std::slice::from_raw_parts_mut(mem as *mut u8, len);
            slice.copy_from_slice(&code);
            let bytes = mem as *const u8;
            clear_cache::clear_cache(bytes, bytes.offset(code.len() as isize));
            Self { bytes, len, labels }
        }
    }

    pub unsafe fn call(&self, offset: usize, iargs: &[u64]) -> Result<(u64, u64), Error> {
        if offset >= self.len {
            return Err(Error::InvalidOffset);
        }
        let addr = self.bytes.offset(offset as isize);
        match iargs {
            &[] => {
                let code: extern "C" fn() -> (u64, u64) = std::mem::transmute(addr);
                Ok(code())
            }
            &[a] => {
                let code: extern "C" fn(u64) -> (u64, u64) = std::mem::transmute(addr);
                Ok(code(a))
            }
            &[a, b] => {
                let code: extern "C" fn(u64, u64) -> (u64, u64) = std::mem::transmute(addr);
                Ok(code(a, b))
            }
            _ => Err(Error::InvalidArgs),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.bytes, self.len).to_vec() }
    }

    pub fn fmt_x86_url(&self) -> String {
        let opcodes = self
            .to_bytes()
            .iter()
            .map(|c| format!("{c:02x}"))
            .collect::<Vec<String>>()
            .join("+");
        format!("https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes={opcodes}&arch=x86-64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly")
    }

    pub fn fmt_arm_url(&self) -> String {
        let opcodes = self
            .to_bytes()
            .chunks_exact(4)
            .map(|c| format!("{:08x}", u32::from_be_bytes(c.try_into().unwrap())))
            .collect::<Vec<String>>()
            .join("+");
        format!("https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes={opcodes}&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly")
    }
}

impl std::fmt::Debug for Executable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.to_bytes())
    }
}

impl Drop for Executable {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.bytes as *mut libc::c_void, self.len as libc::size_t);
        }
    }
}

pub mod aarch64;
pub mod x86_64;

#[cfg(test)]
mod generic_tests;
