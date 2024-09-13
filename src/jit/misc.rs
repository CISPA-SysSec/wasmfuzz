use crate::ir::{ParametricInstruction, TableInstruction, VariableInstruction};

use super::FuncTranslator;
use cranelift::codegen::ir;
use cranelift::{
    frontend::FunctionBuilder,
    prelude::{types::I32, InstBuilder},
};

pub(crate) fn translate_parametric(
    op: &ParametricInstruction,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    match op {
        ParametricInstruction::Drop => {
            let ty = state.peekty();
            if state.dead(bcx) {
                return state.adjust_pop_push(&[ty], &[]);
            }
            state.pop1(ty, bcx);
        }
        ParametricInstruction::Select => {
            let ty = state.peekty_at(1);
            if state.dead(bcx) {
                return state.adjust_pop_push(&[ty, ty, I32], &[ty]);
            }
            // TODO(instrumentation-opportunity): instrument cond
            let cond = state.pop1(I32, bcx);
            let ty = state.peekty2();
            let (a, b) = state.pop2(ty, bcx);
            let val = bcx.ins().select(cond, a, b);
            state.push1(ty, val);
        }
    }
}

fn local_ty(idx: u32, state: &mut FuncTranslator) -> ir::Type {
    if (idx as usize) < state.fspec().ty.params().len() {
        super::wasm2ty(&state.fspec().ty.params()[idx as usize])
    } else {
        let i = idx as usize - state.fspec().ty.params().len();
        super::wasm2ty(&state.fspec().locals[i])
    }
}

pub(crate) fn translate_variable(
    op: &VariableInstruction,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    match *op {
        VariableInstruction::LocalGet(index) => {
            let ty = local_ty(index, state);
            if state.dead(bcx) {
                return state.adjust_pop_push(&[], &[ty]);
            }
            let var = state.get_slot(index);
            let val = bcx.use_var(var);
            state.push1(ty, val);
        }
        VariableInstruction::LocalSet(index) => {
            let ty = local_ty(index, state);
            if state.dead(bcx) {
                return state.adjust_pop_push(&[ty], &[]);
            }
            let val = state.pop1(ty, bcx);
            let var = state.get_slot(index);
            bcx.def_var(var, val);
        }
        VariableInstruction::LocalTee(index) => {
            let ty = local_ty(index, state);
            if state.dead(bcx) {
                return state.adjust_pop_push(&[ty], &[ty]);
            }
            let val = state.peek1(ty, bcx);
            let var = state.get_slot(index);
            bcx.def_var(var, val);
        }
        VariableInstruction::GlobalGet(index) => {
            let ty = super::wasm2ty(&state.spec.globals[index as usize].ty());
            if state.dead(bcx) {
                return state.adjust_pop_push(&[], &[ty]);
            }
            // let vmctx = state.get_vmctx(bcx);
            // let addr = bcx.ins().global_value(state.ptr_ty(), vmctx);
            // let offset = (index as i32 * 8) + 8;
            let addr = state.vmctx.globals.as_ptr();
            let addr = state.host_ptr(bcx, addr);
            let offset = (index as i32) * 8;
            let flags = ir::MemFlags::trusted();
            let val = bcx.ins().load(ty, flags, addr, offset);

            state.push1(ty, val);
        }
        VariableInstruction::GlobalSet(index) => {
            let ty = super::wasm2ty(&state.spec.globals[index as usize].ty());
            if state.dead(bcx) {
                return state.adjust_pop_push(&[ty], &[]);
            }
            let val = state.pop1(ty, bcx);
            // let vmctx = state.get_vmctx(bcx);
            // let addr = bcx.ins().global_value(state.ptr_ty(), vmctx);
            // let offset = (index as i32 * 8) + 8;

            let addr = state.vmctx.globals.as_ptr();
            let addr = state.host_ptr(bcx, addr);
            let offset = (index as i32) * 8;
            let flags = ir::MemFlags::trusted();
            bcx.ins().store(flags, val, addr, offset);

            state.iter_passes(bcx, |pass, ctx| {
                pass.instrument_global_set(index, val, ty, ctx)
            });
        }
    }
}

pub(crate) fn translate_table(
    op: &TableInstruction,
    _state: &mut FuncTranslator,
    _bcx: &mut FunctionBuilder,
) {
    todo!("table op: {:?}", op);
}
