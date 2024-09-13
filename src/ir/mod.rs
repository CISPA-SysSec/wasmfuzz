pub mod operators;
use std::fmt::Display;

pub(crate) use operators::{
    ControlInstruction, FBinaryOp, FUnaryOp, IBinaryOp, IRelOp, ITestOp, IUnaryOp,
    MemoryInstruction, NumericInstruction, ParametricInstruction, TableInstruction,
    VariableInstruction, WFOperator,
};

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub(crate) enum Value {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl Value {
    pub(crate) fn default_for_ty(ty: &ValType) -> Self {
        match ty {
            ValType::I32 => Self::I32(0),
            ValType::I64 => Self::I64(0),
            ValType::F32 => Self::F32(0.),
            ValType::F64 => Self::F64(0.),
            _ => unreachable!(),
        }
    }

    pub(crate) fn ty(&self) -> ValType {
        match self {
            Self::I32(_) => ValType::I32,
            Self::I64(_) => ValType::I64,
            Self::F32(_) => ValType::F32,
            Self::F64(_) => ValType::F64,
        }
    }

    pub(crate) fn as_i32(&self) -> i32 {
        match *self {
            Self::I32(val) => val,
            _ => panic!("as_i32 on {self:?}"),
        }
    }

    pub(crate) fn as_bits(&self) -> u64 {
        match *self {
            Self::I32(val) => val as u64,
            Self::I64(val) => val as u64,
            Self::F32(val) => val.to_bits() as u64,
            Self::F64(val) => val.to_bits(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
// Function-local operator index
pub(crate) struct InsnIdx(pub u32);

impl Display for InsnIdx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl InsnIdx {
    pub(crate) fn i(&self) -> usize {
        self.0 as usize
    }

    pub(crate) fn inc(&self) -> Self {
        Self(self.0 + 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Location {
    pub function: u32,
    pub index: u32,
}

impl Location {
    pub(crate) fn from_u64(val: u64) -> Self {
        let (lo, hi) = (val as u32, (val >> 32) as u32);
        Self {
            index: lo,
            function: hi,
        }
    }

    pub(crate) fn as_u64(&self) -> u64 {
        let (lo, hi) = (self.index, self.function);
        lo as u64 | (hi as u64) << 32
    }
}

pub mod parse;
pub mod parse_cfg;
pub(crate) use parse::FuncSpec;
pub(crate) use parse::ModuleSpec;
use wasmparser::ValType;
pub(crate) mod debuginfo_helper;
pub mod heuristics;
pub mod wasmfuzz_abi;

// TODO(refactoring): move stuff from parse here?
// TODO(refactoring): rename crate::module to crate::ir?
