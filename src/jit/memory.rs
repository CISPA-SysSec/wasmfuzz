use super::FuncTranslator;
use super::util::intern_memflags;
use crate::ir::MemoryInstruction;
use cranelift::codegen::ir;
use cranelift::prelude::InstBuilder;
use cranelift::{frontend::FunctionBuilder, prelude::types::I32};
use wasmparser::MemArg;

// add the static memarg offset as a full pointer-width add (so a large offset
// faults in the guard region instead of wrapping); zero offset stays a no-op
fn fold_static_offset(
    addr: ir::Value,
    offset: u64,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) -> ir::Value {
    if offset == 0 {
        return addr;
    }
    let off = bcx.ins().iconst(state.ptr_ty(), offset as i64);
    bcx.ins().iadd(addr, off)
}

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
    let addr = fold_static_offset(addr, imm.offset, state, bcx);
    let mut flags = ir::MemFlagsData::new();
    flags.set_endianness(ir::Endianness::Little);
    let flags = intern_memflags(bcx, flags);
    let offset = ir::immediates::Offset32::new(0);
    let (load, dfg) = bcx.ins().Load(opcode, result_ty, flags, offset, addr);
    let val = dfg.first_result(load);

    state.iter_passes(bcx, |pass, ctx| {
        pass.instrument_memory_load(addr32, imm.offset as u32, val, result_ty, opcode, ctx)
    });

    let kind = crate::concolic::MemoryAccessKind::from_opcode_and_ty(opcode, result_ty);
    state.fill_concolic_memory_load(result_ty, val, addr32, imm.offset as u32, kind, bcx);
    state.push1(result_ty, val);
}

// Software dirty tracking: record the page(s) this store touches in the
// byte-per-page dirty map, so snapshot-restore only has to copy them back.
//
// The index is the *guest* offset (`addr32 + memarg.offset`), not the host
// address, so the heap base doesn't come into it. Both marks are blind stores:
// no load, no branch, and the map stays hot in L1.
//
// wasm allows unaligned accesses, so a store can straddle a page boundary and
// the last byte's page has to be marked too. For all but a handful of stores
// that's the same byte as the first mark, i.e. a store-to-store forward rather
// than a second cache access.
fn mark_store_dirty(
    addr32: ir::Value,
    static_offset: u64,
    width: u32,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let Some(map_base) = state.get_dirty_map_base(bcx) else {
        return;
    };
    let ptr_ty = state.ptr_ty();
    const PAGE_SHIFT: i64 = 12;

    let offset = bcx.ins().uextend(ptr_ty, addr32);
    let offset = if static_offset == 0 {
        offset
    } else {
        let off = bcx.ins().iconst(ptr_ty, static_offset as i64);
        bcx.ins().iadd(offset, off)
    };

    let one = bcx.ins().iconst(ir::types::I8, 1);
    let flags = ir::MemFlagsData::trusted();

    let first = bcx.ins().ushr_imm_u(offset, PAGE_SHIFT);
    let addr = bcx.ins().iadd(map_base, first);
    bcx.ins()
        .store(flags, one, addr, ir::immediates::Offset32::new(0));

    if width > 1 {
        let last = bcx.ins().iadd_imm_u(offset, (width - 1) as i64);
        let last = bcx.ins().ushr_imm_u(last, PAGE_SHIFT);
        let addr = bcx.ins().iadd(map_base, last);
        bcx.ins()
            .store(flags, one, addr, ir::immediates::Offset32::new(0));
    }
}

// Bytes actually written by a store opcode, which is the narrowed width for
// the Istore8/16/32 forms rather than the width of the value type.
fn store_width(opcode: ir::Opcode, val_ty: ir::Type) -> u32 {
    match opcode {
        ir::Opcode::Istore8 => 1,
        ir::Opcode::Istore16 => 2,
        ir::Opcode::Istore32 => 4,
        _ => val_ty.bytes(),
    }
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
    let addr = fold_static_offset(addr, imm.offset, state, bcx);
    let mut flags = ir::MemFlagsData::new();
    flags.set_endianness(ir::Endianness::Little);
    let flags = intern_memflags(bcx, flags);
    let offset = ir::immediates::Offset32::new(0);

    state.iter_passes(bcx, |pass, ctx| {
        pass.instrument_memory_store(addr32, imm.offset as u32, val, val_ty, opcode, ctx)
    });
    if state.dead(bcx) {
        return;
    }
    mark_store_dirty(
        addr32,
        imm.offset,
        store_width(opcode, val_ty),
        state,
        bcx,
    );
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
