use speedy::{Readable, Writable};

use crate::ir::{
    FBinaryOp, FUnaryOp, IBinaryOp, IRelOp, ITestOp, IUnaryOp,
    operators::{ConversionOp, FRelOp},
};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Readable, Writable)]
#[repr(u8)]
#[speedy(tag_type = u8)]
pub(crate) enum UnaryOp {
    Clz,
    Ctz,
    Popcnt,
    Eqz,

    I32Extend8S,
    I32Extend16S,
    I32WrapI64,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
    I64ExtendI32S,
    I64ExtendI32U,
    I32TruncF32S,
    I32TruncF32U,
    I32TruncF64S,
    I32TruncF64U,
    I64TruncF32S,
    I64TruncF32U,
    I64TruncF64S,
    I64TruncF64U,
    I32TruncSatF32S,
    I32TruncSatF32U,
    I32TruncSatF64S,
    I32TruncSatF64U,
    I64TruncSatF32S,
    I64TruncSatF32U,
    I64TruncSatF64S,
    I64TruncSatF64U,
    F32DemoteF64,
    F64PromoteF32,
    F32ConvertI32S,
    F32ConvertI32U,
    F32ConvertI64S,
    F32ConvertI64U,
    F64ConvertI32S,
    F64ConvertI32U,
    F64ConvertI64S,
    F64ConvertI64U,
    I32ReinterpretF32,
    I64ReinterpretF64,
    F32ReinterpretI32,
    F64ReinterpretI64,

    FAbs,
    FNeg,
    FSqrt,
    FCeil,
    FFloor,
    FTrunc,
    FNearest,
}

impl From<&IUnaryOp> for UnaryOp {
    fn from(val: &IUnaryOp) -> Self {
        match val {
            IUnaryOp::Clz => Self::Clz,
            IUnaryOp::Ctz => Self::Ctz,
            IUnaryOp::Popcnt => Self::Popcnt,
        }
    }
}

impl From<&ITestOp> for UnaryOp {
    fn from(val: &ITestOp) -> Self {
        match val {
            ITestOp::Eqz => Self::Eqz,
        }
    }
}

impl From<&ConversionOp> for UnaryOp {
    fn from(val: &ConversionOp) -> Self {
        match val {
            ConversionOp::I32Extend8S => Self::I32Extend8S,
            ConversionOp::I32Extend16S => Self::I32Extend16S,
            ConversionOp::I32WrapI64 => Self::I32WrapI64,
            ConversionOp::I64Extend8S => Self::I64Extend8S,
            ConversionOp::I64Extend16S => Self::I64Extend16S,
            ConversionOp::I64Extend32S => Self::I64Extend32S,
            ConversionOp::I64ExtendI32S => Self::I64ExtendI32S,
            ConversionOp::I64ExtendI32U => Self::I64ExtendI32U,
            ConversionOp::I32TruncF32S => Self::I32TruncF32S,
            ConversionOp::I32TruncF32U => Self::I32TruncF32U,
            ConversionOp::I32TruncF64S => Self::I32TruncF64S,
            ConversionOp::I32TruncF64U => Self::I32TruncF64U,
            ConversionOp::I64TruncF32S => Self::I64TruncF32S,
            ConversionOp::I64TruncF32U => Self::I64TruncF32U,
            ConversionOp::I64TruncF64S => Self::I64TruncF64S,
            ConversionOp::I64TruncF64U => Self::I64TruncF64U,
            ConversionOp::I32TruncSatF32S => Self::I32TruncSatF32S,
            ConversionOp::I32TruncSatF32U => Self::I32TruncSatF32U,
            ConversionOp::I32TruncSatF64S => Self::I32TruncSatF64S,
            ConversionOp::I32TruncSatF64U => Self::I32TruncSatF64U,
            ConversionOp::I64TruncSatF32S => Self::I64TruncSatF32S,
            ConversionOp::I64TruncSatF32U => Self::I64TruncSatF32U,
            ConversionOp::I64TruncSatF64S => Self::I64TruncSatF64S,
            ConversionOp::I64TruncSatF64U => Self::I64TruncSatF64U,
            ConversionOp::F32DemoteF64 => Self::F32DemoteF64,
            ConversionOp::F64PromoteF32 => Self::F64PromoteF32,
            ConversionOp::F32ConvertI32S => Self::F32ConvertI32S,
            ConversionOp::F32ConvertI32U => Self::F32ConvertI32U,
            ConversionOp::F32ConvertI64S => Self::F32ConvertI64S,
            ConversionOp::F32ConvertI64U => Self::F32ConvertI64U,
            ConversionOp::F64ConvertI32S => Self::F64ConvertI32S,
            ConversionOp::F64ConvertI32U => Self::F64ConvertI32U,
            ConversionOp::F64ConvertI64S => Self::F64ConvertI64S,
            ConversionOp::F64ConvertI64U => Self::F64ConvertI64U,
            ConversionOp::I32ReinterpretF32 => Self::I32ReinterpretF32,
            ConversionOp::I64ReinterpretF64 => Self::I64ReinterpretF64,
            ConversionOp::F32ReinterpretI32 => Self::F32ReinterpretI32,
            ConversionOp::F64ReinterpretI64 => Self::F64ReinterpretI64,
        }
    }
}

impl From<&FUnaryOp> for UnaryOp {
    fn from(val: &FUnaryOp) -> Self {
        match val {
            FUnaryOp::Abs => Self::FAbs,
            FUnaryOp::Neg => Self::FNeg,
            FUnaryOp::Sqrt => Self::FSqrt,
            FUnaryOp::Ceil => Self::FCeil,
            FUnaryOp::Floor => Self::FFloor,
            FUnaryOp::Trunc => Self::FTrunc,
            FUnaryOp::Nearest => Self::FNearest,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Readable, Writable)]
#[repr(u8)]
#[speedy(tag_type = u8)]
pub(crate) enum BinaryOp {
    // arith
    Add,
    Sub,
    Mul,
    DivS,
    DivU,
    RemS,
    RemU,
    And,
    Or,
    Xor,
    Shl,
    ShrS,
    ShrU,
    Rotl,
    Rotr,

    // rel ops
    Eq,
    Ne,
    LtU,
    LtS,
    GtU,
    GtS,
    LeU,
    LeS,
    GeU,
    GeS,

    // float rel
    FEq,
    FNe,
    FLt,
    FGt,
    FLe,
    FGe,

    // float arith
    FAdd,
    FSub,
    FMul,
    FDiv,
    FMin,
    FMax,
    FCopysign,
}

impl From<&IBinaryOp> for BinaryOp {
    fn from(val: &IBinaryOp) -> Self {
        match val {
            IBinaryOp::Add => Self::Add,
            IBinaryOp::Sub => Self::Sub,
            IBinaryOp::Mul => Self::Mul,
            IBinaryOp::DivS => Self::DivS,
            IBinaryOp::DivU => Self::DivU,
            IBinaryOp::RemS => Self::RemS,
            IBinaryOp::RemU => Self::RemU,
            IBinaryOp::And => Self::And,
            IBinaryOp::Or => Self::Or,
            IBinaryOp::Xor => Self::Xor,
            IBinaryOp::Shl => Self::Shl,
            IBinaryOp::ShrS => Self::ShrS,
            IBinaryOp::ShrU => Self::ShrU,
            IBinaryOp::Rotl => Self::Rotl,
            IBinaryOp::Rotr => Self::Rotr,
        }
    }
}

impl From<&IRelOp> for BinaryOp {
    fn from(val: &IRelOp) -> Self {
        match val {
            IRelOp::Eq => Self::Eq,
            IRelOp::Ne => Self::Ne,
            IRelOp::LtU => Self::LtU,
            IRelOp::LtS => Self::LtS,
            IRelOp::GtU => Self::GtU,
            IRelOp::GtS => Self::GtS,
            IRelOp::LeU => Self::LeU,
            IRelOp::LeS => Self::LeS,
            IRelOp::GeU => Self::GeU,
            IRelOp::GeS => Self::GeS,
        }
    }
}

impl From<&FRelOp> for BinaryOp {
    fn from(val: &FRelOp) -> Self {
        match val {
            FRelOp::Eq => Self::FEq,
            FRelOp::Ne => Self::FNe,
            FRelOp::Lt => Self::FLt,
            FRelOp::Gt => Self::FGt,
            FRelOp::Le => Self::FLe,
            FRelOp::Ge => Self::FGe,
        }
    }
}

impl From<&FBinaryOp> for BinaryOp {
    fn from(val: &FBinaryOp) -> Self {
        match val {
            FBinaryOp::Add => Self::FAdd,
            FBinaryOp::Sub => Self::FSub,
            FBinaryOp::Mul => Self::FMul,
            FBinaryOp::Div => Self::FDiv,
            FBinaryOp::Min => Self::FMin,
            FBinaryOp::Max => Self::FMax,
            FBinaryOp::Copysign => Self::FCopysign,
        }
    }
}
