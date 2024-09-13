use super::{InsnIdx, Value};
use wasmparser::{FuncType, MemArg, Operator};

#[derive(Debug)]
pub(crate) enum IUnaryOp {
    Clz,
    Ctz,
    Popcnt,
}

#[derive(Debug)]
pub(crate) enum IBinaryOp {
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
}

#[derive(Debug)]
pub(crate) enum FUnaryOp {
    Abs,
    Neg,
    Sqrt,
    Ceil,
    Floor,
    Trunc,
    Nearest,
}

#[derive(Debug)]
pub(crate) enum FBinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Min,
    Max,
    Copysign,
}

#[derive(Debug)]
pub(crate) enum ITestOp {
    Eqz,
}

#[derive(Debug)]
pub(crate) enum IRelOp {
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
}

#[derive(Debug)]
pub(crate) enum FRelOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

#[derive(Debug)]
pub(crate) enum ConversionOp {
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
}

#[derive(Debug)]
pub(crate) enum NumericInstruction {
    Const(Value),
    I32UnOp(IUnaryOp),
    I32BinOp(IBinaryOp),
    I64UnOp(IUnaryOp),
    I64BinOp(IBinaryOp),
    F32UnOp(FUnaryOp),
    F32BinOp(FBinaryOp),
    F64UnOp(FUnaryOp),
    F64BinOp(FBinaryOp),
    I32TestOp(ITestOp),
    I64TestOp(ITestOp),
    I32RelOp(IRelOp),
    I64RelOp(IRelOp),
    F32RelOp(FRelOp),
    F64RelOp(FRelOp),
    ConversionOp(ConversionOp),
}

#[derive(Debug)]
pub(crate) enum MemoryInstruction {
    I32Load(MemArg),
    I32Load8U(MemArg),
    I32Load8S(MemArg),
    I32Load16U(MemArg),
    I32Load16S(MemArg),
    I64Load(MemArg),
    I64Load8U(MemArg),
    I64Load8S(MemArg),
    I64Load16U(MemArg),
    I64Load16S(MemArg),
    I64Load32U(MemArg),
    I64Load32S(MemArg),
    I32Store(MemArg),
    I32Store8(MemArg),
    I32Store16(MemArg),
    I64Store(MemArg),
    I64Store8(MemArg),
    I64Store16(MemArg),
    I64Store32(MemArg),
    F32Load(MemArg),
    F64Load(MemArg),
    F32Store(MemArg),
    F64Store(MemArg),
    MemorySize,
    MemoryGrow,
    MemoryFill,
    MemoryCopy,
    #[allow(unused)]
    MemoryInit(u32),
    #[allow(unused)]
    DataDrop(u32),
}

#[derive(Debug)]
pub(crate) enum VariableInstruction {
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
}

#[derive(Debug)]
pub(crate) enum ParametricInstruction {
    Drop,
    Select,
}

#[allow(unused)]
#[derive(Debug)]
pub(crate) enum TableInstruction {
    TableGet(u32),
    TableSet(u32),
    TableSize(u32),
    TableGrow(u32),
    TableFill(u32),
    TableCopy(u32, u32),
    TableInit(u32, u32),
    ElemDrop(u32),
}

#[derive(Debug)]
pub(crate) enum ControlInstruction {
    Nop,
    Unreachable,
    End {
        block_ty: FuncType,
        starts_new_block: bool,
    },
    Block {
        ty: FuncType,
    },
    Loop {
        ty: FuncType,
    },
    If {
        ty: FuncType,
        else_operator_index: Option<InsnIdx>,
        end_operator_index: InsnIdx,
    },
    Else {
        if_operator_index: InsnIdx,
        end_operator_index: InsnIdx,
        target_params: FuncType,
    },
    Br {
        cfg_target: InsnIdx,
        // relative_depth: u32,
        target_params: FuncType,
    },
    BrIf {
        cfg_target: InsnIdx,
        // relative_depth: u32,
        target_params: FuncType,
    },
    BrTable {
        targets: Vec<InsnIdx>,
        default: InsnIdx,
    },
    Return,
    Call {
        function_index: u32,
        function_ty: FuncType,
    },
    CallIndirect {
        table_index: u32,
        function_ty: FuncType,
    },
}

#[derive(Debug)]
pub(crate) enum WFOperator {
    Numeric(NumericInstruction),
    Parametric(ParametricInstruction),
    Variable(VariableInstruction),
    Table(TableInstruction),
    Memory(MemoryInstruction),
    Control(ControlInstruction),
    Builtin {
        name: String,
        ty: FuncType,
    },
    #[allow(unused)]
    TodoUnimplemented(String),
}

pub(crate) fn op_to_const(op: Operator) -> Value {
    match op {
        Operator::I32Const { value } => Value::I32(value),
        Operator::I64Const { value } => Value::I64(value),
        Operator::F32Const { value } => Value::F32(f32::from_bits(value.bits())),
        Operator::F64Const { value } => Value::F64(f64::from_bits(value.bits())),
        _ => unreachable!(),
    }
}

pub(crate) fn translate_operator(op: Operator) -> WFOperator {
    use ConversionOp as COP;
    use NumericInstruction as NumInst;
    use VariableInstruction as VarInstr;
    use WFOperator as WFO;
    match op {
        Operator::LocalGet { local_index } => WFO::Variable(VarInstr::LocalGet(local_index)),
        Operator::LocalSet { local_index } => WFO::Variable(VarInstr::LocalSet(local_index)),
        Operator::LocalTee { local_index } => WFO::Variable(VarInstr::LocalTee(local_index)),
        Operator::GlobalGet { global_index } => WFO::Variable(VarInstr::GlobalGet(global_index)),
        Operator::GlobalSet { global_index } => WFO::Variable(VarInstr::GlobalSet(global_index)),

        Operator::I32Const { .. }
        | Operator::I64Const { .. }
        | Operator::F32Const { .. }
        | Operator::F64Const { .. } => WFO::Numeric(NumInst::Const(op_to_const(op))),

        Operator::I32Clz => WFO::Numeric(NumInst::I32UnOp(IUnaryOp::Clz)),
        Operator::I32Ctz => WFO::Numeric(NumInst::I32UnOp(IUnaryOp::Ctz)),
        Operator::I32Popcnt => WFO::Numeric(NumInst::I32UnOp(IUnaryOp::Popcnt)),

        Operator::I64Clz => WFO::Numeric(NumInst::I64UnOp(IUnaryOp::Clz)),
        Operator::I64Ctz => WFO::Numeric(NumInst::I64UnOp(IUnaryOp::Ctz)),
        Operator::I64Popcnt => WFO::Numeric(NumInst::I64UnOp(IUnaryOp::Popcnt)),

        Operator::F32Abs => WFO::Numeric(NumInst::F32UnOp(FUnaryOp::Abs)),
        Operator::F32Neg => WFO::Numeric(NumInst::F32UnOp(FUnaryOp::Neg)),
        Operator::F32Sqrt => WFO::Numeric(NumInst::F32UnOp(FUnaryOp::Sqrt)),
        Operator::F32Ceil => WFO::Numeric(NumInst::F32UnOp(FUnaryOp::Ceil)),
        Operator::F32Floor => WFO::Numeric(NumInst::F32UnOp(FUnaryOp::Floor)),
        Operator::F32Trunc => WFO::Numeric(NumInst::F32UnOp(FUnaryOp::Trunc)),
        Operator::F32Nearest => WFO::Numeric(NumInst::F32UnOp(FUnaryOp::Nearest)),

        Operator::F64Abs => WFO::Numeric(NumInst::F64UnOp(FUnaryOp::Abs)),
        Operator::F64Neg => WFO::Numeric(NumInst::F64UnOp(FUnaryOp::Neg)),
        Operator::F64Sqrt => WFO::Numeric(NumInst::F64UnOp(FUnaryOp::Sqrt)),
        Operator::F64Ceil => WFO::Numeric(NumInst::F64UnOp(FUnaryOp::Ceil)),
        Operator::F64Floor => WFO::Numeric(NumInst::F64UnOp(FUnaryOp::Floor)),
        Operator::F64Trunc => WFO::Numeric(NumInst::F64UnOp(FUnaryOp::Trunc)),
        Operator::F64Nearest => WFO::Numeric(NumInst::F64UnOp(FUnaryOp::Nearest)),

        Operator::I32Add => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::Add)),
        Operator::I32Sub => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::Sub)),
        Operator::I32Mul => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::Mul)),
        Operator::I32DivS => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::DivS)),
        Operator::I32DivU => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::DivU)),
        Operator::I32RemS => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::RemS)),
        Operator::I32RemU => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::RemU)),
        Operator::I32And => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::And)),
        Operator::I32Or => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::Or)),
        Operator::I32Xor => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::Xor)),
        Operator::I32Shl => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::Shl)),
        Operator::I32ShrS => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::ShrS)),
        Operator::I32ShrU => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::ShrU)),
        Operator::I32Rotl => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::Rotl)),
        Operator::I32Rotr => WFO::Numeric(NumInst::I32BinOp(IBinaryOp::Rotr)),

        Operator::I64Add => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::Add)),
        Operator::I64Sub => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::Sub)),
        Operator::I64Mul => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::Mul)),
        Operator::I64DivS => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::DivS)),
        Operator::I64DivU => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::DivU)),
        Operator::I64RemS => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::RemS)),
        Operator::I64RemU => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::RemU)),
        Operator::I64And => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::And)),
        Operator::I64Or => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::Or)),
        Operator::I64Xor => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::Xor)),
        Operator::I64Shl => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::Shl)),
        Operator::I64ShrS => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::ShrS)),
        Operator::I64ShrU => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::ShrU)),
        Operator::I64Rotl => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::Rotl)),
        Operator::I64Rotr => WFO::Numeric(NumInst::I64BinOp(IBinaryOp::Rotr)),

        Operator::F32Add => WFO::Numeric(NumInst::F32BinOp(FBinaryOp::Add)),
        Operator::F32Sub => WFO::Numeric(NumInst::F32BinOp(FBinaryOp::Sub)),
        Operator::F32Mul => WFO::Numeric(NumInst::F32BinOp(FBinaryOp::Mul)),
        Operator::F32Div => WFO::Numeric(NumInst::F32BinOp(FBinaryOp::Div)),
        Operator::F32Min => WFO::Numeric(NumInst::F32BinOp(FBinaryOp::Min)),
        Operator::F32Max => WFO::Numeric(NumInst::F32BinOp(FBinaryOp::Max)),
        Operator::F32Copysign => WFO::Numeric(NumInst::F32BinOp(FBinaryOp::Copysign)),

        Operator::F64Add => WFO::Numeric(NumInst::F64BinOp(FBinaryOp::Add)),
        Operator::F64Sub => WFO::Numeric(NumInst::F64BinOp(FBinaryOp::Sub)),
        Operator::F64Mul => WFO::Numeric(NumInst::F64BinOp(FBinaryOp::Mul)),
        Operator::F64Div => WFO::Numeric(NumInst::F64BinOp(FBinaryOp::Div)),
        Operator::F64Min => WFO::Numeric(NumInst::F64BinOp(FBinaryOp::Min)),
        Operator::F64Max => WFO::Numeric(NumInst::F64BinOp(FBinaryOp::Max)),
        Operator::F64Copysign => WFO::Numeric(NumInst::F64BinOp(FBinaryOp::Copysign)),

        Operator::I32Eqz => WFO::Numeric(NumInst::I32TestOp(ITestOp::Eqz)),
        Operator::I64Eqz => WFO::Numeric(NumInst::I64TestOp(ITestOp::Eqz)),

        Operator::I32Eq => WFO::Numeric(NumInst::I32RelOp(IRelOp::Eq)),
        Operator::I32Ne => WFO::Numeric(NumInst::I32RelOp(IRelOp::Ne)),
        Operator::I32LtU => WFO::Numeric(NumInst::I32RelOp(IRelOp::LtU)),
        Operator::I32LtS => WFO::Numeric(NumInst::I32RelOp(IRelOp::LtS)),
        Operator::I32GtU => WFO::Numeric(NumInst::I32RelOp(IRelOp::GtU)),
        Operator::I32GtS => WFO::Numeric(NumInst::I32RelOp(IRelOp::GtS)),
        Operator::I32LeU => WFO::Numeric(NumInst::I32RelOp(IRelOp::LeU)),
        Operator::I32LeS => WFO::Numeric(NumInst::I32RelOp(IRelOp::LeS)),
        Operator::I32GeU => WFO::Numeric(NumInst::I32RelOp(IRelOp::GeU)),
        Operator::I32GeS => WFO::Numeric(NumInst::I32RelOp(IRelOp::GeS)),

        Operator::I64Eq => WFO::Numeric(NumInst::I64RelOp(IRelOp::Eq)),
        Operator::I64Ne => WFO::Numeric(NumInst::I64RelOp(IRelOp::Ne)),
        Operator::I64LtU => WFO::Numeric(NumInst::I64RelOp(IRelOp::LtU)),
        Operator::I64LtS => WFO::Numeric(NumInst::I64RelOp(IRelOp::LtS)),
        Operator::I64GtU => WFO::Numeric(NumInst::I64RelOp(IRelOp::GtU)),
        Operator::I64GtS => WFO::Numeric(NumInst::I64RelOp(IRelOp::GtS)),
        Operator::I64LeU => WFO::Numeric(NumInst::I64RelOp(IRelOp::LeU)),
        Operator::I64LeS => WFO::Numeric(NumInst::I64RelOp(IRelOp::LeS)),
        Operator::I64GeU => WFO::Numeric(NumInst::I64RelOp(IRelOp::GeU)),
        Operator::I64GeS => WFO::Numeric(NumInst::I64RelOp(IRelOp::GeS)),

        Operator::F32Eq => WFO::Numeric(NumInst::F32RelOp(FRelOp::Eq)),
        Operator::F32Ne => WFO::Numeric(NumInst::F32RelOp(FRelOp::Ne)),
        Operator::F32Lt => WFO::Numeric(NumInst::F32RelOp(FRelOp::Lt)),
        Operator::F32Gt => WFO::Numeric(NumInst::F32RelOp(FRelOp::Gt)),
        Operator::F32Le => WFO::Numeric(NumInst::F32RelOp(FRelOp::Le)),
        Operator::F32Ge => WFO::Numeric(NumInst::F32RelOp(FRelOp::Ge)),

        Operator::F64Eq => WFO::Numeric(NumInst::F64RelOp(FRelOp::Eq)),
        Operator::F64Ne => WFO::Numeric(NumInst::F64RelOp(FRelOp::Ne)),
        Operator::F64Lt => WFO::Numeric(NumInst::F64RelOp(FRelOp::Lt)),
        Operator::F64Gt => WFO::Numeric(NumInst::F64RelOp(FRelOp::Gt)),
        Operator::F64Le => WFO::Numeric(NumInst::F64RelOp(FRelOp::Le)),
        Operator::F64Ge => WFO::Numeric(NumInst::F64RelOp(FRelOp::Ge)),

        Operator::I32Extend8S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I32Extend8S)),
        Operator::I32Extend16S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I32Extend16S)),
        Operator::I64Extend8S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I64Extend8S)),
        Operator::I64Extend16S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I64Extend16S)),
        Operator::I64Extend32S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I64Extend32S)),
        Operator::I64ExtendI32S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I64ExtendI32S)),
        Operator::I64ExtendI32U => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I64ExtendI32U)),
        Operator::I32WrapI64 => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I32WrapI64)),
        Operator::I32TruncF32S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I32TruncF32S)),
        Operator::I32TruncF32U => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I32TruncF32U)),
        Operator::I32TruncF64S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I32TruncF64S)),
        Operator::I32TruncF64U => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I32TruncF64U)),
        Operator::I64TruncF32S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I64TruncF32S)),
        Operator::I64TruncF32U => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I64TruncF32U)),
        Operator::I64TruncF64S => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I64TruncF64S)),
        Operator::I64TruncF64U => WFO::Numeric(NumInst::ConversionOp(ConversionOp::I64TruncF64U)),
        Operator::I32TruncSatF32S => WFO::Numeric(NumInst::ConversionOp(COP::I32TruncSatF32S)),
        Operator::I32TruncSatF32U => WFO::Numeric(NumInst::ConversionOp(COP::I32TruncSatF32U)),
        Operator::I32TruncSatF64S => WFO::Numeric(NumInst::ConversionOp(COP::I32TruncSatF64S)),
        Operator::I32TruncSatF64U => WFO::Numeric(NumInst::ConversionOp(COP::I32TruncSatF64U)),
        Operator::I64TruncSatF32S => WFO::Numeric(NumInst::ConversionOp(COP::I64TruncSatF32S)),
        Operator::I64TruncSatF32U => WFO::Numeric(NumInst::ConversionOp(COP::I64TruncSatF32U)),
        Operator::I64TruncSatF64S => WFO::Numeric(NumInst::ConversionOp(COP::I64TruncSatF64S)),
        Operator::I64TruncSatF64U => WFO::Numeric(NumInst::ConversionOp(COP::I64TruncSatF64U)),
        Operator::F32DemoteF64 => WFO::Numeric(NumInst::ConversionOp(COP::F32DemoteF64)),
        Operator::F64PromoteF32 => WFO::Numeric(NumInst::ConversionOp(COP::F64PromoteF32)),
        Operator::F32ConvertI32S => WFO::Numeric(NumInst::ConversionOp(COP::F32ConvertI32S)),
        Operator::F32ConvertI32U => WFO::Numeric(NumInst::ConversionOp(COP::F32ConvertI32U)),
        Operator::F32ConvertI64S => WFO::Numeric(NumInst::ConversionOp(COP::F32ConvertI64S)),
        Operator::F32ConvertI64U => WFO::Numeric(NumInst::ConversionOp(COP::F32ConvertI64U)),
        Operator::F64ConvertI32S => WFO::Numeric(NumInst::ConversionOp(COP::F64ConvertI32S)),
        Operator::F64ConvertI32U => WFO::Numeric(NumInst::ConversionOp(COP::F64ConvertI32U)),
        Operator::F64ConvertI64S => WFO::Numeric(NumInst::ConversionOp(COP::F64ConvertI64S)),
        Operator::F64ConvertI64U => WFO::Numeric(NumInst::ConversionOp(COP::F64ConvertI64U)),
        Operator::I32ReinterpretF32 => WFO::Numeric(NumInst::ConversionOp(COP::I32ReinterpretF32)),
        Operator::I64ReinterpretF64 => WFO::Numeric(NumInst::ConversionOp(COP::I64ReinterpretF64)),
        Operator::F32ReinterpretI32 => WFO::Numeric(NumInst::ConversionOp(COP::F32ReinterpretI32)),
        Operator::F64ReinterpretI64 => WFO::Numeric(NumInst::ConversionOp(COP::F64ReinterpretI64)),

        Operator::I32Load { memarg } => WFO::Memory(MemoryInstruction::I32Load(memarg)),
        Operator::I32Load8U { memarg } => WFO::Memory(MemoryInstruction::I32Load8U(memarg)),
        Operator::I32Load8S { memarg } => WFO::Memory(MemoryInstruction::I32Load8S(memarg)),
        Operator::I32Load16U { memarg } => WFO::Memory(MemoryInstruction::I32Load16U(memarg)),
        Operator::I32Load16S { memarg } => WFO::Memory(MemoryInstruction::I32Load16S(memarg)),
        Operator::I64Load8U { memarg } => WFO::Memory(MemoryInstruction::I64Load8U(memarg)),
        Operator::I64Load8S { memarg } => WFO::Memory(MemoryInstruction::I64Load8S(memarg)),
        Operator::I64Load16U { memarg } => WFO::Memory(MemoryInstruction::I64Load16U(memarg)),
        Operator::I64Load16S { memarg } => WFO::Memory(MemoryInstruction::I64Load16S(memarg)),
        Operator::I64Load32U { memarg } => WFO::Memory(MemoryInstruction::I64Load32U(memarg)),
        Operator::I64Load32S { memarg } => WFO::Memory(MemoryInstruction::I64Load32S(memarg)),
        Operator::I64Load { memarg } => WFO::Memory(MemoryInstruction::I64Load(memarg)),
        Operator::I32Store { memarg } => WFO::Memory(MemoryInstruction::I32Store(memarg)),
        Operator::I32Store8 { memarg } => WFO::Memory(MemoryInstruction::I32Store8(memarg)),
        Operator::I32Store16 { memarg } => WFO::Memory(MemoryInstruction::I32Store16(memarg)),
        Operator::I64Store { memarg } => WFO::Memory(MemoryInstruction::I64Store(memarg)),
        Operator::I64Store8 { memarg } => WFO::Memory(MemoryInstruction::I64Store8(memarg)),
        Operator::I64Store16 { memarg } => WFO::Memory(MemoryInstruction::I64Store16(memarg)),
        Operator::I64Store32 { memarg } => WFO::Memory(MemoryInstruction::I64Store32(memarg)),
        Operator::F32Load { memarg } => WFO::Memory(MemoryInstruction::F32Load(memarg)),
        Operator::F64Load { memarg } => WFO::Memory(MemoryInstruction::F64Load(memarg)),
        Operator::F32Store { memarg } => WFO::Memory(MemoryInstruction::F32Store(memarg)),
        Operator::F64Store { memarg } => WFO::Memory(MemoryInstruction::F64Store(memarg)),

        Operator::MemoryGrow { .. } => WFO::Memory(MemoryInstruction::MemoryGrow),
        Operator::MemorySize { .. } => WFO::Memory(MemoryInstruction::MemorySize),
        Operator::MemoryCopy { .. } => WFO::Memory(MemoryInstruction::MemoryCopy),
        Operator::MemoryFill { .. } => WFO::Memory(MemoryInstruction::MemoryFill),
        Operator::MemoryInit { data_index, .. } => {
            WFO::Memory(MemoryInstruction::MemoryInit(data_index))
        }
        Operator::DataDrop { data_index, .. } => {
            WFO::Memory(MemoryInstruction::DataDrop(data_index))
        }

        Operator::Select => WFO::Parametric(ParametricInstruction::Select),
        Operator::Drop => WFO::Parametric(ParametricInstruction::Drop),

        Operator::TableGet { table } => WFO::Table(TableInstruction::TableGet(table)),
        Operator::TableSet { table } => WFO::Table(TableInstruction::TableSet(table)),
        Operator::TableSize { table } => WFO::Table(TableInstruction::TableSize(table)),
        Operator::TableGrow { table } => WFO::Table(TableInstruction::TableGrow(table)),
        Operator::TableFill { table } => WFO::Table(TableInstruction::TableFill(table)),
        Operator::TableCopy {
            src_table,
            dst_table,
        } => WFO::Table(TableInstruction::TableCopy(src_table, dst_table)),
        Operator::TableInit { elem_index, table } => {
            WFO::Table(TableInstruction::TableInit(elem_index, table))
        }
        Operator::ElemDrop { elem_index } => WFO::Table(TableInstruction::ElemDrop(elem_index)),

        Operator::Unreachable
        | Operator::Nop
        | Operator::Call { .. }
        | Operator::CallIndirect { .. }
        | Operator::Block { .. }
        | Operator::BrIf { .. }
        | Operator::If { .. }
        | Operator::Else
        | Operator::Return
        | Operator::End => {
            panic!("control instruction {op:?} should be handled with cfg analysis");
        }
        _ => {
            eprintln!("TODO: unimplemented operator: {op:?}");
            WFO::TodoUnimplemented(format!("{:?}", op))
        }
    }
}
