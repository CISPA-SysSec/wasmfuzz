use cranelift::codegen::ir;
use cranelift::frontend::FunctionBuilder;
use cranelift::prelude::{InstBuilder, IntCC, MemFlags, Type, Value, types::I64};

use crate::ir::{Location, heuristics::Libfunc};

use super::VMContext;
use super::{
    CompilationKind, FuncTranslator,
    module::TrapKind,
    tracing::{trace_cmp, trace_memcmp, trace_strcmp},
};

fn bail(state: &mut FuncTranslator, bcx: &mut FunctionBuilder) -> bool {
    state.dead(bcx) || state.builtin_level > 0
}

// TODO(refactoring): move this elsewhere. we've moved all coverage
// instrumentation but tracing still lives here

pub(crate) fn instrument_func(
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
    location: Location,
) {
    if !bail(state, bcx)
        && state
            .options
            .swarm
            .avoid_functions
            .contains(&location.function)
    {
        state.trap_here(TrapKind::SwarmShortCircuit(Some(location)), bcx);
    }
    if !bail(state, bcx) && state.options.kind == CompilationKind::Tracing {
        if matches!(
            state.fspec().known_libfunc,
            Some(Libfunc::Memcmp | Libfunc::Strncmp | Libfunc::Strncasecmp)
        ) {
            let a = state.get_slot(0, bcx, ir::types::I32);
            let b = state.get_slot(1, bcx, ir::types::I32);
            let n = state.get_slot(2, bcx, ir::types::I32);
            let a = bcx.use_var(a);
            let b = bcx.use_var(b);
            let n = bcx.use_var(n);
            trace_memcmp(state, bcx, location, a, b, n)
        }
        if matches!(
            state.fspec().known_libfunc,
            Some(Libfunc::Strcmp | Libfunc::Strcasecmp)
        ) {
            let a = state.get_slot(0, bcx, ir::types::I32);
            let b = state.get_slot(1, bcx, ir::types::I32);
            let a = bcx.use_var(a);
            let b = bcx.use_var(b);
            trace_strcmp(state, bcx, location, a, b)
        }
        if let Some(libfunc) = state.fspec().known_libfunc {
            if state.options.is_concolic() {
                super::concolic::translate_concolic_trace_libcall(libfunc, state, bcx);
            }
        }
    }
}

pub(crate) fn instrument_bb(
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
    location: Location,
) {
    instrument_bb_fuel(state, bcx, location);
}

fn instrument_bb_fuel(state: &mut FuncTranslator, bcx: &mut FunctionBuilder, location: Location) {
    if bail(state, bcx) || !state.options.tracking.fuel {
        return;
    }

    let f = state.fspec();
    let bb_start = f.operator_basic_block[location.index as usize];
    let bb_end = f
        .basic_block_starts
        .iter()
        .find(|&&x| x > bb_start)
        .map(|x| x.0)
        .unwrap_or(f.operators.len() as u32);
    let bb_size = (bb_end - bb_start.0) as i64;

    let gv_vmctx = state.get_vmctx(bcx);
    let vmctx = bcx.ins().global_value(state.ptr_ty(), gv_vmctx);
    let fuel = bcx.ins().load(
        I64,
        MemFlags::trusted(),
        vmctx,
        std::mem::offset_of!(VMContext, fuel) as i32,
    );

    let is_lt = bcx.ins().icmp_imm(IntCC::UnsignedLessThan, fuel, bb_size);
    let trap_code = state.get_trap_code(TrapKind::OutOfFuel(Some(location)));
    bcx.ins().trapnz(is_lt, trap_code);

    let fuel = bcx.ins().iadd_imm(fuel, -bb_size);
    bcx.ins().store(
        MemFlags::trusted(),
        fuel,
        vmctx,
        std::mem::offset_of!(VMContext, fuel) as i32,
    );
}

pub(crate) fn instrument_cmp(
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
    location: Location,
    value_ty: Type,
    value_a: Value,
    value_b: Value,
) {
    if bail(state, bcx) {
        return;
    }

    if state.options.kind == CompilationKind::Tracing {
        trace_cmp(state, bcx, location, value_a, value_b, value_ty);
    }
}
