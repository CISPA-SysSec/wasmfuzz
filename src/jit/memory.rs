use super::FuncTranslator;
use crate::ir::MemoryInstruction;
use cranelift::codegen::ir;
use cranelift::prelude::InstBuilder;
use cranelift::{frontend::FunctionBuilder, prelude::types::I32};
use wasmparser::MemArg;

fn translate_load(
    imm: &MemArg,
    opcode: ir::Opcode,
    result_ty: ir::Type,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    if state.dead(bcx) {
        return state.adjust_pop_push(&[I32], &[result_ty]);
    }

    let addr32 = state.pop1(I32, bcx);
    let base = state.get_heap_base(bcx);
    let addr = bcx.ins().uextend(state.ptr_ty(), addr32);
    let addr = bcx.ins().iadd(base, addr);
    let mut flags = ir::MemFlags::new();
    flags.set_endianness(ir::Endianness::Little);
    // NOTE: We're not verifying load bounds with imm.offset!
    let offset = ir::immediates::Offset32::new(imm.offset as i32);
    let (load, dfg) = bcx.ins().Load(opcode, result_ty, flags, offset, addr);
    let val = dfg.first_result(load);

    state.iter_passes(bcx, |pass, ctx| {
        pass.instrument_memory_load(addr32, imm.offset as u32, val, result_ty, opcode, ctx)
    });

    let kind = crate::concolic::MemoryAccessKind::from_opcode_and_ty(opcode, result_ty);
    state.fill_concolic_memory_load(result_ty, val, addr32, imm.offset as u32, kind, bcx);
    state.push1(result_ty, val);
}

fn translate_store(
    imm: &MemArg,
    opcode: ir::Opcode,
    val_ty: ir::Type,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    if state.dead(bcx) {
        return state.adjust_pop_push(&[I32, val_ty], &[]);
    }

    let val = state.pop1(val_ty, bcx);
    let addr32 = state.pop1(I32, bcx);
    let base = state.get_heap_base(bcx);
    let addr = bcx.ins().uextend(state.ptr_ty(), addr32);
    let addr = bcx.ins().iadd(base, addr);
    let mut flags = ir::MemFlags::new();
    flags.set_endianness(ir::Endianness::Little);
    let offset = ir::immediates::Offset32::new(imm.offset as i32);

    state.iter_passes(bcx, |pass, ctx| {
        pass.instrument_memory_store(addr32, imm.offset as u32, val, val_ty, opcode, ctx)
    });
    if state.dead(bcx) {
        return;
    }
    bcx.ins().Store(opcode, val_ty, flags, offset, val, addr);
    let kind = crate::concolic::MemoryAccessKind::from_opcode_and_ty(opcode, val_ty);
    state.concolic_memory_store(val, addr32, imm.offset as u32, kind, bcx);
}

pub(crate) fn translate_memory(
    op: &MemoryInstruction,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    use MemoryInstruction::*;
    use ir::Opcode;
    use ir::types;
    match op {
        I32Load(imm) => translate_load(imm, Opcode::Load, types::I32, state, bcx),
        I32Load8U(imm) => translate_load(imm, Opcode::Uload8, types::I32, state, bcx),
        I32Load8S(imm) => translate_load(imm, Opcode::Sload8, types::I32, state, bcx),
        I32Load16U(imm) => translate_load(imm, Opcode::Uload16, types::I32, state, bcx),
        I32Load16S(imm) => translate_load(imm, Opcode::Sload16, types::I32, state, bcx),
        I64Load(imm) => translate_load(imm, Opcode::Load, types::I64, state, bcx),
        I64Load8U(imm) => translate_load(imm, Opcode::Uload8, types::I64, state, bcx),
        I64Load8S(imm) => translate_load(imm, Opcode::Sload8, types::I64, state, bcx),
        I64Load16U(imm) => translate_load(imm, Opcode::Uload16, types::I64, state, bcx),
        I64Load16S(imm) => translate_load(imm, Opcode::Sload16, types::I64, state, bcx),
        I64Load32U(imm) => translate_load(imm, Opcode::Uload32, types::I64, state, bcx),
        I64Load32S(imm) => translate_load(imm, Opcode::Sload32, types::I64, state, bcx),
        F32Load(imm) => translate_load(imm, Opcode::Load, types::F32, state, bcx),
        F64Load(imm) => translate_load(imm, Opcode::Load, types::F64, state, bcx),

        I32Store(imm) => translate_store(imm, Opcode::Store, types::I32, state, bcx),
        I32Store8(imm) => translate_store(imm, Opcode::Istore8, types::I32, state, bcx),
        I32Store16(imm) => translate_store(imm, Opcode::Istore16, types::I32, state, bcx),
        I64Store(imm) => translate_store(imm, Opcode::Store, types::I64, state, bcx),
        I64Store8(imm) => translate_store(imm, Opcode::Istore8, types::I64, state, bcx),
        I64Store16(imm) => translate_store(imm, Opcode::Istore16, types::I64, state, bcx),
        I64Store32(imm) => translate_store(imm, Opcode::Istore32, types::I64, state, bcx),
        F32Store(imm) => translate_store(imm, Opcode::Store, types::F32, state, bcx),
        F64Store(imm) => translate_store(imm, Opcode::Store, types::F64, state, bcx),

        MemorySize => {
            if state.dead(bcx) {
                return state.adjust_pop_push(&[], &[I32]);
            }
            state.jit_builtin_call("MemorySize", None, bcx);
        }
        MemoryGrow => {
            if state.dead(bcx) {
                return state.adjust_pop_push(&[I32], &[I32]);
            }
            state.jit_builtin_call("MemoryGrow", None, bcx);
        }
        MemoryFill => {
            if state.dead(bcx) {
                return state.adjust_pop_push(&[I32, I32, I32], &[]);
            }
            state.jit_builtin_call("MemoryFill", None, bcx);
        }
        MemoryCopy => {
            if state.dead(bcx) {
                return state.adjust_pop_push(&[I32, I32, I32], &[]);
            }
            state.jit_builtin_call("MemoryCopy", None, bcx);
        }
        /*
        MemoryInit(_) => {}
        DataDrop(_) => {}
        */
        _ => {
            panic!("non-jitted memory op: {op:?}");
        }
    }
}
