use super::FuncTranslator;
use super::instrumentation::instrument_cmp;
use crate::ir::operators::ConversionOp;
use crate::ir::{
    FBinaryOp, FUnaryOp, IBinaryOp, IRelOp, ITestOp, IUnaryOp, NumericInstruction,
    operators::FRelOp,
};
use cranelift::codegen::ir;
use cranelift::prelude::{FloatCC, IntCC, MemFlags, types::*};
use cranelift::{frontend::FunctionBuilder, prelude::InstBuilder};

pub(crate) fn translate_const(
    val: &crate::ir::Value,
    bcx: &mut FunctionBuilder,
) -> (ir::Type, ir::Value) {
    use crate::ir::Value;
    use ir::types;
    match val {
        Value::I32(val) => (I32, bcx.ins().iconst(types::I32, *val as u32 as i64)),
        Value::I64(val) => (I64, bcx.ins().iconst(types::I64, *val)),
        Value::F32(val) => (F32, bcx.ins().f32const(*val)),
        Value::F64(val) => (F64, bcx.ins().f64const(*val)),
    }
}

fn translate_iunop(op: &IUnaryOp, ty: Type, state: &mut FuncTranslator, bcx: &mut FunctionBuilder) {
    let val = state.pop1(ty, bcx);
    let res = match op {
        IUnaryOp::Clz => bcx.ins().clz(val),
        IUnaryOp::Ctz => bcx.ins().ctz(val),
        IUnaryOp::Popcnt => bcx.ins().popcnt(val),
    };
    state.fill_concolic_unop(ty, res, op.into(), val, bcx);
    state.push1(ty, res);
}

fn translate_ibinop(
    op: &IBinaryOp,
    ty: Type,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let (a, b) = state.pop2(ty, bcx);
    let val = match op {
        IBinaryOp::Add => bcx.ins().iadd(a, b),
        IBinaryOp::Sub => bcx.ins().isub(a, b),
        IBinaryOp::Mul => bcx.ins().imul(a, b),
        IBinaryOp::DivS => bcx.ins().sdiv(a, b),
        IBinaryOp::DivU => bcx.ins().udiv(a, b),
        IBinaryOp::RemS => bcx.ins().srem(a, b),
        IBinaryOp::RemU => bcx.ins().urem(a, b),
        IBinaryOp::And => bcx.ins().band(a, b),
        IBinaryOp::Or => bcx.ins().bor(a, b),
        IBinaryOp::Xor => bcx.ins().bxor(a, b),
        IBinaryOp::Shl => bcx.ins().ishl(a, b),
        IBinaryOp::ShrS => bcx.ins().sshr(a, b),
        IBinaryOp::ShrU => bcx.ins().ushr(a, b),
        IBinaryOp::Rotl => bcx.ins().rotl(a, b),
        IBinaryOp::Rotr => bcx.ins().rotr(a, b),
    };
    state.fill_concolic_binop(ty, val, op.into(), a, b, ty, bcx);
    state.push1(ty, val);
}

fn translate_itestop(
    op: &ITestOp,
    ty: Type,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    match op {
        ITestOp::Eqz => {
            let arg = state.pop1(ty, bcx);
            let zero = bcx.ins().iconst(ty, 0);
            state.iter_passes(bcx, |pass, ctx| pass.instrument_cmp(ty, arg, zero, ctx));
            instrument_cmp(state, bcx, state.loc(), ty, arg, zero);
            if state.dead(bcx) {
                return state.adjust_pop_push(&[], &[I32]);
            }
            let res = bcx.ins().icmp_imm(IntCC::Equal, arg, 0);
            let res = bcx.ins().uextend(I32, res);
            state.fill_concolic_unop(I32, res, op.into(), arg, bcx);
            state.push1(I32, res);
        }
    }
}

fn translate_irelop(op: &IRelOp, ty: Type, state: &mut FuncTranslator, bcx: &mut FunctionBuilder) {
    let cc = match op {
        IRelOp::Eq => IntCC::Equal,
        IRelOp::Ne => IntCC::NotEqual,
        IRelOp::LtU => IntCC::UnsignedLessThan,
        IRelOp::LtS => IntCC::SignedLessThan,
        IRelOp::GtU => IntCC::UnsignedGreaterThan,
        IRelOp::GtS => IntCC::SignedGreaterThan,
        IRelOp::LeU => IntCC::UnsignedLessThanOrEqual,
        IRelOp::LeS => IntCC::SignedLessThanOrEqual,
        IRelOp::GeU => IntCC::UnsignedGreaterThanOrEqual,
        IRelOp::GeS => IntCC::SignedGreaterThanOrEqual,
    };
    let (a, b) = state.pop2(ty, bcx);
    state.iter_passes(bcx, |pass, ctx| pass.instrument_cmp(ty, a, b, ctx));
    instrument_cmp(state, bcx, state.loc(), ty, a, b);
    if state.dead(bcx) {
        return state.adjust_pop_push(&[], &[I32]);
    }
    let val = bcx.ins().icmp(cc, a, b);
    let val = bcx.ins().uextend(I32, val);
    state.fill_concolic_binop(I32, val, op.into(), a, b, ty, bcx);
    state.push1(I32, val);
}

fn translate_funop(op: &FUnaryOp, ty: Type, state: &mut FuncTranslator, bcx: &mut FunctionBuilder) {
    let val = state.pop1(ty, bcx);
    let res = match op {
        FUnaryOp::Abs => bcx.ins().fabs(val),
        FUnaryOp::Neg => bcx.ins().fneg(val),
        FUnaryOp::Sqrt => bcx.ins().sqrt(val),
        FUnaryOp::Ceil => bcx.ins().ceil(val),
        FUnaryOp::Floor => bcx.ins().floor(val),
        FUnaryOp::Trunc => bcx.ins().trunc(val),
        FUnaryOp::Nearest => bcx.ins().nearest(val),
    };
    state.fill_concolic_unop(ty, res, op.into(), val, bcx);
    state.push1(ty, res);
}

fn translate_fbinop(
    op: &FBinaryOp,
    ty: Type,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let (a, b) = state.pop2(ty, bcx);
    let val = match op {
        FBinaryOp::Add => bcx.ins().fadd(a, b),
        FBinaryOp::Sub => bcx.ins().fsub(a, b),
        FBinaryOp::Mul => bcx.ins().fmul(a, b),
        FBinaryOp::Div => bcx.ins().fdiv(a, b),
        FBinaryOp::Min => bcx.ins().fmin(a, b),
        FBinaryOp::Max => bcx.ins().fmax(a, b),
        FBinaryOp::Copysign => bcx.ins().fcopysign(a, b),
    };
    state.fill_concolic_binop(ty, val, op.into(), a, b, ty, bcx);
    state.push1(ty, val);
}

fn translate_frelop(op: &FRelOp, ty: Type, state: &mut FuncTranslator, bcx: &mut FunctionBuilder) {
    let cc = match op {
        FRelOp::Eq => FloatCC::Equal,
        FRelOp::Ne => FloatCC::NotEqual,
        FRelOp::Lt => FloatCC::LessThan,
        FRelOp::Gt => FloatCC::GreaterThan,
        FRelOp::Le => FloatCC::LessThanOrEqual,
        FRelOp::Ge => FloatCC::GreaterThanOrEqual,
    };
    let (a, b) = state.pop2(ty, bcx);
    state.iter_passes(bcx, |pass, ctx| pass.instrument_cmp(ty, a, b, ctx));
    instrument_cmp(state, bcx, state.loc(), ty, a, b);
    if state.dead(bcx) {
        return state.adjust_pop_push(&[], &[I32]);
    }
    let val = bcx.ins().fcmp(cc, a, b);
    let val = bcx.ins().uextend(I32, val);
    state.fill_concolic_binop(I32, val, op.into(), a, b, ty, bcx);
    state.push1(I32, val);
}

fn conversion_op_ty(op: &ConversionOp) -> (Type, Type) {
    match op {
        ConversionOp::I32Extend8S | ConversionOp::I32Extend16S => (I32, I32),
        ConversionOp::I64Extend8S | ConversionOp::I64Extend16S | ConversionOp::I64Extend32S => {
            (I64, I64)
        }
        ConversionOp::I64ExtendI32S | ConversionOp::I64ExtendI32U => (I32, I64),
        ConversionOp::I32WrapI64 => (I64, I32),
        ConversionOp::F64ConvertI64U | ConversionOp::F64ConvertI64S => (I64, F64),
        ConversionOp::F64ConvertI32U | ConversionOp::F64ConvertI32S => (I32, F64),
        ConversionOp::F32ConvertI64U | ConversionOp::F32ConvertI64S => (I64, F32),
        ConversionOp::F32ConvertI32U | ConversionOp::F32ConvertI32S => (I32, F32),
        ConversionOp::F64PromoteF32 => (F32, F64),
        ConversionOp::F32DemoteF64 => (F64, F32),
        ConversionOp::I64TruncF32S
        | ConversionOp::I64TruncF32U
        | ConversionOp::I64TruncSatF32S
        | ConversionOp::I64TruncSatF32U => (F32, I64),
        ConversionOp::I64TruncF64S
        | ConversionOp::I64TruncF64U
        | ConversionOp::I64TruncSatF64S
        | ConversionOp::I64TruncSatF64U => (F64, I64),
        ConversionOp::I32TruncF32S
        | ConversionOp::I32TruncF32U
        | ConversionOp::I32TruncSatF32S
        | ConversionOp::I32TruncSatF32U => (F32, I32),
        ConversionOp::I32TruncF64S
        | ConversionOp::I32TruncF64U
        | ConversionOp::I32TruncSatF64S
        | ConversionOp::I32TruncSatF64U => (F64, I32),
        ConversionOp::F32ReinterpretI32 => (I32, F32),
        ConversionOp::F64ReinterpretI64 => (I64, F64),
        ConversionOp::I32ReinterpretF32 => (F32, I32),
        ConversionOp::I64ReinterpretF64 => (F64, I64),
    }
}

fn translate_conversion_op(
    op: &ConversionOp,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let (from_ty, to_ty) = conversion_op_ty(op);

    let val = state.pop1(from_ty, bcx);
    let res = match op {
        ConversionOp::I32Extend8S => {
            let val = bcx.ins().ireduce(I8, val);
            bcx.ins().sextend(I32, val)
        }
        ConversionOp::I32Extend16S => {
            let val = bcx.ins().ireduce(I16, val);
            bcx.ins().sextend(I32, val)
        }
        ConversionOp::I64Extend8S => {
            let val = bcx.ins().ireduce(I8, val);
            bcx.ins().sextend(I64, val)
        }
        ConversionOp::I64Extend16S => {
            let val = bcx.ins().ireduce(I16, val);
            bcx.ins().sextend(I64, val)
        }
        ConversionOp::I64Extend32S => {
            let val = bcx.ins().ireduce(I32, val);
            bcx.ins().sextend(I64, val)
        }
        ConversionOp::I64ExtendI32S => bcx.ins().sextend(I64, val),
        ConversionOp::I64ExtendI32U => bcx.ins().uextend(I64, val),
        ConversionOp::I32WrapI64 => bcx.ins().ireduce(I32, val),
        ConversionOp::F64ConvertI64U | ConversionOp::F64ConvertI32U => {
            bcx.ins().fcvt_from_uint(F64, val)
        }
        ConversionOp::F64ConvertI64S | ConversionOp::F64ConvertI32S => {
            bcx.ins().fcvt_from_sint(F64, val)
        }
        ConversionOp::F32ConvertI64S | ConversionOp::F32ConvertI32S => {
            bcx.ins().fcvt_from_sint(F32, val)
        }
        ConversionOp::F32ConvertI64U | ConversionOp::F32ConvertI32U => {
            bcx.ins().fcvt_from_uint(F32, val)
        }
        ConversionOp::F64PromoteF32 => bcx.ins().fpromote(F64, val),
        ConversionOp::F32DemoteF64 => bcx.ins().fdemote(F32, val),
        ConversionOp::I64TruncF64S | ConversionOp::I64TruncF32S => bcx.ins().fcvt_to_sint(I64, val),
        ConversionOp::I32TruncF64S | ConversionOp::I32TruncF32S => bcx.ins().fcvt_to_sint(I32, val),
        ConversionOp::I64TruncF64U | ConversionOp::I64TruncF32U => bcx.ins().fcvt_to_uint(I64, val),
        ConversionOp::I32TruncF64U | ConversionOp::I32TruncF32U => bcx.ins().fcvt_to_uint(I32, val),
        ConversionOp::I64TruncSatF64S | ConversionOp::I64TruncSatF32S => {
            bcx.ins().fcvt_to_sint_sat(I64, val)
        }
        ConversionOp::I32TruncSatF64S | ConversionOp::I32TruncSatF32S => {
            bcx.ins().fcvt_to_sint_sat(I32, val)
        }
        ConversionOp::I64TruncSatF64U | ConversionOp::I64TruncSatF32U => {
            bcx.ins().fcvt_to_uint_sat(I64, val)
        }
        ConversionOp::I32TruncSatF64U | ConversionOp::I32TruncSatF32U => {
            bcx.ins().fcvt_to_uint_sat(I32, val)
        }
        ConversionOp::F32ReinterpretI32 => bcx.ins().bitcast(F32, MemFlags::new(), val),
        ConversionOp::F64ReinterpretI64 => bcx.ins().bitcast(F64, MemFlags::new(), val),
        ConversionOp::I32ReinterpretF32 => bcx.ins().bitcast(I32, MemFlags::new(), val),
        ConversionOp::I64ReinterpretF64 => bcx.ins().bitcast(I64, MemFlags::new(), val),
    };
    state.fill_concolic_unop(to_ty, res, op.into(), val, bcx);
    state.push1(to_ty, res);
}

pub(crate) fn translate_numeric(
    op: &NumericInstruction,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    use NumericInstruction as NumIns;
    if state.dead(bcx) {
        return match op {
            NumIns::Const(val) => state.adjust_pop_push(&[], &[super::wasm2ty(&val.ty())]),
            NumIns::I32UnOp(_) => state.adjust_pop_push(&[I32], &[I32]),
            NumIns::I32BinOp(_) => state.adjust_pop_push(&[I32, I32], &[I32]),
            NumIns::I64UnOp(_) => state.adjust_pop_push(&[I64], &[I64]),
            NumIns::I64BinOp(_) => state.adjust_pop_push(&[I64, I64], &[I64]),
            NumIns::F32UnOp(_) => state.adjust_pop_push(&[F32], &[F32]),
            NumIns::F32BinOp(_) => state.adjust_pop_push(&[F32, F32], &[F32]),
            NumIns::F64UnOp(_) => state.adjust_pop_push(&[F64], &[F64]),
            NumIns::F64BinOp(_) => state.adjust_pop_push(&[F64, F64], &[F64]),
            NumIns::I32TestOp(_) => state.adjust_pop_push(&[I32], &[I32]),
            NumIns::I64TestOp(_) => state.adjust_pop_push(&[I64], &[I32]),
            NumIns::I32RelOp(_) => state.adjust_pop_push(&[I32, I32], &[I32]),
            NumIns::I64RelOp(_) => state.adjust_pop_push(&[I64, I64], &[I32]),
            NumIns::F32RelOp(_) => state.adjust_pop_push(&[F32, F32], &[I32]),
            NumIns::F64RelOp(_) => state.adjust_pop_push(&[F64, F64], &[I32]),
            NumIns::ConversionOp(convop) => {
                let (fromty, toty) = conversion_op_ty(convop);
                state.adjust_pop_push(&[fromty], &[toty])
            }
        };
    }

    match op {
        NumericInstruction::Const(val) => {
            let (ty, val) = translate_const(val, bcx);
            state.set_concolic_concrete(ty, val, bcx);
            state.push1(ty, val);
        }
        NumericInstruction::I32UnOp(unop) => translate_iunop(unop, I32, state, bcx),
        NumericInstruction::I32BinOp(binop) => translate_ibinop(binop, I32, state, bcx),
        NumericInstruction::I64UnOp(unop) => translate_iunop(unop, I64, state, bcx),
        NumericInstruction::I64BinOp(binop) => translate_ibinop(binop, I64, state, bcx),
        NumericInstruction::F32UnOp(unop) => translate_funop(unop, F32, state, bcx),
        NumericInstruction::F32BinOp(binop) => translate_fbinop(binop, F32, state, bcx),
        NumericInstruction::F64UnOp(unop) => translate_funop(unop, F64, state, bcx),
        NumericInstruction::F64BinOp(binop) => translate_fbinop(binop, F64, state, bcx),
        NumericInstruction::I32TestOp(testop) => translate_itestop(testop, I32, state, bcx),
        NumericInstruction::I64TestOp(testop) => translate_itestop(testop, I64, state, bcx),
        NumericInstruction::I32RelOp(relop) => translate_irelop(relop, I32, state, bcx),
        NumericInstruction::I64RelOp(relop) => translate_irelop(relop, I64, state, bcx),
        NumericInstruction::F32RelOp(relop) => translate_frelop(relop, F32, state, bcx),
        NumericInstruction::F64RelOp(relop) => translate_frelop(relop, F64, state, bcx),
        NumericInstruction::ConversionOp(op) => translate_conversion_op(op, state, bcx),
    }
}
