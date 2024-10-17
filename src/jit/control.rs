use crate::instrumentation::FuncIdx;
use crate::ir::WFOperator;
use crate::{ir::ControlInstruction, AbortCode};

use super::concolic::{
    translate_concolic_push_path_constraint_eq, translate_concolic_push_path_constraint_nz,
};
use super::util::wasm2tys;
use super::FuncTranslator;
use codegen::ir::SigRef;
use cranelift::codegen::ir::{self, ArgumentPurpose};
use cranelift::prelude::types::*;
use cranelift::prelude::*;

fn params_augument_concolic(params: &mut Vec<Value>, state: &mut FuncTranslator) {
    if state.options.is_concolic() {
        let symvals = params
            .iter()
            .map(|val| state.get_concolic(val))
            .collect::<Vec<_>>();
        params.extend_from_slice(&symvals);
    }
}

pub(crate) fn translate_control<'a, 'b, 's>(
    op: &ControlInstruction,
    state: &'a mut FuncTranslator<'b, 's>,
    bcx: &mut FunctionBuilder,
) where
    'b: 'a,
{
    match op {
        ControlInstruction::Nop => {
            if !state.dead(bcx) {
                bcx.ins().nop();
            }
        }

        ControlInstruction::Unreachable => {
            if !state.dead(bcx) {
                bcx.ins()
                    .trap(state.trap_abort(AbortCode::UnreachableReached));
                state.mark_dead(bcx);
            }
        }

        ControlInstruction::End {
            block_ty,
            starts_new_block,
        } => {
            let tys = wasm2tys(block_ty.results());
            let block = state.block(state.ip, bcx);
            if state.dead(bcx) {
                // handle unreachable ends with value-returning blocks:
                // loop i32
                //   br 0
                state.pop_control_frame();
            } else {
                let mut params = state.popn(&tys, bcx);
                state.pop_control_frame();
                params_augument_concolic(&mut params, state);
                bcx.ins().jump(block, &params);
                state.mark_dead(bcx);
            }

            let mut block_return_values = Vec::new();
            for ty in block_ty.results() {
                let param = bcx.append_block_param(block, super::wasm2ty(ty));
                block_return_values.push(param);
            }

            if state.options.is_concolic() {
                for (param, ty) in block_return_values.iter().zip(&tys) {
                    let param_symex = bcx.append_block_param(block, types::I32);
                    state.set_concolic(*ty, *param, param_symex, bcx);
                }
            }
            bcx.switch_to_block(block);
            state.pushn(&tys, &block_return_values);
            let edge = crate::instrumentation::Edge::new(state.fidx, state.ip, state.ip.inc());
            state.iter_passes(bcx, |pass, ctx| pass.instrument_edge(edge, ctx));
            if *starts_new_block {
                let next = state.block(state.ip.inc(), bcx);
                if !state.dead(bcx) {
                    bcx.ins().jump(next, &[]);
                }
                bcx.switch_to_block(next);
            }
        }

        ControlInstruction::Block { ty } | ControlInstruction::Loop { ty } => {
            let block = state.block(state.ip, bcx);
            let tys = wasm2tys(ty.params());
            if !state.dead(bcx) {
                let mut params = state.popn(&tys, bcx);
                params_augument_concolic(&mut params, state);
                bcx.ins().jump(block, &params);
                state.mark_dead(bcx);
            }
            let mut block_params = Vec::new();
            for ty in ty.params() {
                let param = bcx.append_block_param(block, super::wasm2ty(ty));
                block_params.push(param);
            }
            if state.options.is_concolic() {
                for (param, ty) in block_params.iter().zip(&tys) {
                    let param_symex = bcx.append_block_param(block, types::I32);
                    state.set_concolic(*ty, *param, param_symex, bcx);
                }
            }
            if matches!(op, ControlInstruction::Block { .. }) {
                bcx.seal_block(block); // we can only re-enter loop headers
            }
            bcx.switch_to_block(block);
            state.push_control_frame();
            state.pushn(&tys, &block_params);
        }

        ControlInstruction::If {
            ty: _ty,
            else_operator_index,
            end_operator_index,
        } => {
            if state.dead(bcx) {
                state.adjust_pop_push(&[I32], &[]);
                return state.push_control_frame();
            }

            let cond = state.pop1(I32, bcx);

            if state.options.is_concolic() {
                let caller = state.loc();
                translate_concolic_push_path_constraint_nz(cond, caller, state, bcx);
            }

            state.push_control_frame();
            let cont = state.block(state.ip, bcx);
            // TODO: sanity-check and args?

            let intermediate_block = bcx.create_block();
            bcx.ins().brif(cond, cont, &[], intermediate_block, &[]);
            bcx.seal_block(intermediate_block);

            bcx.switch_to_block(intermediate_block);
            if let Some(else_index) = else_operator_index {
                let edge = crate::instrumentation::Edge::new(state.fidx, state.ip, *else_index);
                state.iter_passes(bcx, |pass, ctx| pass.instrument_edge(edge, ctx));
                let else_block = state.block(*else_index, bcx);
                if !state.dead(bcx) {
                    bcx.ins().jump(else_block, &[]);
                }
                bcx.seal_block(else_block);
            } else {
                let edge =
                    crate::instrumentation::Edge::new(state.fidx, state.ip, *end_operator_index);
                state.iter_passes(bcx, |pass, ctx| pass.instrument_edge(edge, ctx));
                let end_block = state.block(*end_operator_index, bcx);
                if !state.dead(bcx) {
                    bcx.ins().jump(end_block, &[]);
                }
            }

            bcx.seal_block(cont);
            bcx.switch_to_block(cont);
        }

        ControlInstruction::Else {
            if_operator_index: _if_operator_index,
            end_operator_index,
            target_params,
        } => {
            debug_assert!(target_params.results().is_empty());
            if state.dead(bcx) {
                // state.adjust_pop_push_fty(target_params);
                state.pop_control_frame();
                state.push_control_frame();
            } else {
                let end_block = state.block(*end_operator_index, bcx);
                let param_tys = wasm2tys(target_params.params());
                let mut params = state.popn(&param_tys, bcx);
                params_augument_concolic(&mut params, state);
                bcx.ins().jump(end_block, &params);
                state.mark_dead(bcx);
            }
            let else_block = state.block(state.ip, bcx);
            bcx.switch_to_block(else_block);
        }

        ControlInstruction::Br {
            cfg_target,
            target_params,
            ..
        } => {
            if state.dead(bcx) {
                return state.adjust_pop_push_fty(target_params);
            }
            let target = state.block(*cfg_target, bcx);
            let param_tys = wasm2tys(target_params.params());
            let mut params = state.popn(&param_tys, bcx);
            params_augument_concolic(&mut params, state);
            let edge = crate::instrumentation::Edge::new(state.fidx, state.ip, *cfg_target);
            state.iter_passes(bcx, |pass, ctx| pass.instrument_edge(edge, ctx));
            if !state.dead(bcx) {
                bcx.ins().jump(target, &params);
                state.mark_dead(bcx);
            }
            // NOTE: br should always be followed by end?
        }

        ControlInstruction::BrIf {
            cfg_target,
            target_params,
            ..
        } => {
            if state.dead(bcx) {
                return state.adjust_pop_push(&[I32], &[]);
            }
            let target = state.block(*cfg_target, bcx);
            let else_block = bcx.create_block();
            let cond = state.pop1(I32, bcx);

            if state.options.is_concolic() {
                let caller = state.loc();
                translate_concolic_push_path_constraint_nz(cond, caller, state, bcx);
            }

            let jump_block = bcx.create_block();
            bcx.ins().brif(cond, jump_block, &[], else_block, &[]);

            bcx.seal_block(jump_block);
            bcx.switch_to_block(jump_block);
            let edge = crate::instrumentation::Edge::new(state.fidx, state.ip, *cfg_target);
            state.iter_passes(bcx, |pass, ctx| pass.instrument_edge(edge, ctx));
            let mut params = state.peekn(target_params.params().len(), bcx);
            if !state.dead(bcx) {
                params_augument_concolic(&mut params, state);
                bcx.ins().jump(target, &params);
            }

            bcx.seal_block(else_block);
            bcx.switch_to_block(else_block);
            let edge = crate::instrumentation::Edge::new(state.fidx, state.ip, state.ip.inc());
            state.iter_passes(bcx, |pass, ctx| pass.instrument_edge(edge, ctx));
        }

        ControlInstruction::BrTable { targets, default } => {
            // TODO: not sure how this plays into block parameters
            if state.dead(bcx) {
                return state.adjust_pop_push(&[I32], &[]);
            }
            let val = state.pop1(I32, bcx);

            if state.options.is_concolic() {
                // TODO: explicitly solve for targets with different funcs?
                let caller = state.loc();
                translate_concolic_push_path_constraint_eq(val, I32, caller, state, bcx);
            }

            let default_target = state.block(*default, bcx);
            let default_block = bcx.create_block();
            let jump_blocks: Vec<Block> = targets.iter().map(|_| bcx.create_block()).collect();

            let data = JumpTableData::new(
                bcx.func.dfg.block_call(default_block, &[]),
                &jump_blocks
                    .iter()
                    .map(|block| bcx.func.dfg.block_call(*block, &[]))
                    .collect::<Vec<_>>(),
            );
            let jt = bcx.create_jump_table(data);
            bcx.ins().br_table(val, jt);
            state.mark_dead(bcx);

            for (target, block) in targets.iter().zip(jump_blocks.iter()) {
                bcx.seal_block(*block);
                bcx.switch_to_block(*block);
                let edge = crate::instrumentation::Edge::new(state.fidx, state.ip, *target);
                state.iter_passes(bcx, |pass, ctx| pass.instrument_edge(edge, ctx));
                if !state.dead(bcx) {
                    let target_block = state.block(*target, bcx);
                    bcx.ins().jump(target_block, &[]);
                }
            }

            bcx.seal_block(default_block);
            bcx.switch_to_block(default_block);
            let edge = crate::instrumentation::Edge::new(state.fidx, state.ip, *default);
            state.iter_passes(bcx, |pass, ctx| pass.instrument_edge(edge, ctx));
            if !state.dead(bcx) {
                bcx.ins().jump(default_target, &[]);
                state.mark_dead(bcx);
            }
        }

        ControlInstruction::Return => {
            state.iter_passes(bcx, |pass, ctx| pass.instrument_function_ret(ctx));

            let rets = wasm2tys(state.fspec().ty.results());
            if state.dead(bcx) {
                return state.adjust_pop_push(&rets, &[]);
            }
            let mut rvals = state.popn(&rets, bcx);
            if state.options.is_concolic() {
                let concolic_vars = rvals
                    .iter()
                    .map(|el| state.get_concolic(el))
                    .collect::<Vec<_>>();
                rvals.extend_from_slice(&concolic_vars);
            }
            bcx.ins().return_(&rvals); // TODO: refactor for easier inlining?
            state.mark_dead(bcx);
        }

        ControlInstruction::Call {
            function_index,
            function_ty,
        } => {
            if state.dead(bcx) {
                return state.adjust_pop_push_fty(function_ty);
            }

            // if bcx.is_pristine() { .. }
            if bcx.func.layout.entry_block().is_none() {
                bcx.ins().nop(); // FIXME(cranelift): thread 'main' panicked at 'Function is empty'
            }

            if state.spec.functions[*function_index as usize].is_stub {
                let fspec = &state.spec.functions[*function_index as usize];
                let op = WFOperator::Builtin {
                    name: fspec._symbol.clone().unwrap(),
                    ty: fspec.ty.clone(),
                };
                state.translate_op(&op, bcx, state.ip);
            } else {
                translate_call(
                    function_ty,
                    state,
                    bcx,
                    Callee::Direct {
                        function_index: *function_index,
                    },
                );
            }
        }

        ControlInstruction::CallIndirect {
            function_ty,
            table_index,
        } => {
            // TODO: call_indirect support is very scuffed.
            // we should at least confirm the target signature.

            if state.dead(bcx) {
                state.adjust_pop_push(&[I32], &[]); // callee idx
                return state.adjust_pop_push_fty(function_ty);
            }

            let callee_idx = state.pop1(I32, bcx);

            if state.options.is_concolic() {
                let caller = state.loc();
                translate_concolic_push_path_constraint_eq(callee_idx, I32, caller, state, bcx);
            }

            let sig = {
                let mut signature = Signature::new(isa::CallConv::Fast);
                for param in function_ty.params() {
                    signature.params.push(AbiParam::new(super::wasm2ty(param)));
                }
                for ret in function_ty.results() {
                    signature.returns.push(AbiParam::new(super::wasm2ty(ret)));
                }

                if state.options.is_concolic() {
                    let symval = AbiParam::new(ir::types::I32);
                    for _ in function_ty.params() {
                        signature.params.push(symval);
                    }
                    for _ in function_ty.results() {
                        signature.returns.push(symval);
                    }
                }

                signature.params.push(ir::AbiParam::special(
                    state.ptr_ty(),
                    ir::ArgumentPurpose::VMContext,
                ));
                signature
            };

            let sigref = state.import_signature(sig, bcx);
            let table_len;
            let table_ptr;
            {
                let table = &state.vmctx.tables[*table_index as usize];
                table_ptr = table.as_ptr();
                table_len = table.len();
            }
            let ptr = state.host_ptr(bcx, table_ptr);
            // bounds check
            let bounds = bcx.ins().iconst(I32, table_len as i64);
            let oob = bcx
                .ins()
                .icmp(IntCC::UnsignedGreaterThanOrEqual, callee_idx, bounds);
            bcx.ins().trapnz(oob, ir::TrapCode::TableOutOfBounds);

            let callee_idx = bcx.ins().sextend(I64, callee_idx);
            let callee_offset = bcx.ins().imul_imm(callee_idx, 8);
            let ptr = bcx.ins().iadd(ptr, callee_offset);
            let callee = bcx
                .ins()
                .load(state.ptr_ty(), ir::MemFlags::trusted(), ptr, 0);

            translate_call(function_ty, state, bcx, Callee::Indirect { sigref, callee });
            // TODO: insert edges?
        }
    }
}

enum Callee {
    Direct { function_index: u32 },
    Indirect { sigref: SigRef, callee: Value },
}

fn translate_call(
    function_ty: &wasmparser::FuncType,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
    callee: Callee,
) {
    if state.dead(bcx) {
        return state.adjust_pop_push_fty(function_ty);
    }

    let param_tys = wasm2tys(function_ty.params());
    let return_tys = wasm2tys(function_ty.results());
    let mut params = state.popn(&param_tys, bcx);
    let instr_callee = match callee {
        Callee::Direct { function_index } => Some(function_index),
        Callee::Indirect { .. } => None,
    };
    state.iter_passes(bcx, |pass, ctx| {
        pass.instrument_call(instr_callee.map(FuncIdx), &params, &param_tys, ctx)
    });
    if state.dead(bcx) {
        return state.adjust_pop_push(&[], &return_tys);
    }

    params_augument_concolic(&mut params, state);
    let vmctx = bcx
        .func
        .special_param(ArgumentPurpose::VMContext)
        .expect("Missing vmctx parameter");

    params.push(vmctx);

    let call = match callee {
        Callee::Direct { function_index } => {
            bcx.ins().call(state.func_ref(function_index), &params)
        }
        Callee::Indirect { sigref, callee } => bcx.ins().call_indirect(sigref, callee, &params),
    };

    let mut inst_results = bcx.inst_results(call).to_vec();

    if state.options.is_concolic() {
        let symvals = inst_results.split_off(function_ty.results().len());
        for ((val, symval), ty) in inst_results.iter().zip(symvals).zip(&return_tys) {
            state.set_concolic(*ty, *val, symval, bcx);
        }
    }

    state.iter_passes(bcx, |pass, ctx| {
        pass.instrument_call_return(instr_callee.map(FuncIdx), &inst_results, &return_tys, ctx)
    });
    state.pushn(&return_tys, &inst_results);
}
