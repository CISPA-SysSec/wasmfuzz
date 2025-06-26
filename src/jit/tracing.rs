use cranelift::prelude::*;

use crate::ir::Location;

use super::{vmcontext::VMContext, CompilationKind, FuncTranslator};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
// TODO: move?
pub(crate) enum CmpLog {
    U16(u16, u16),
    U32(u32, u32),
    U64(u64, u64),
    Memcmp(Vec<u8>, Vec<u8>),
}

// TODO(instrumentation): trace conditional jmp for ngrams?

pub(crate) fn trace_cmp(
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
    caller: Location,
    mut a: Value,
    mut b: Value,
    ty: types::Type,
) {
    if state.dead(bcx) || state.options.kind != CompilationKind::Tracing {
        return;
    }

    if ty == types::I32 {
        a = bcx.ins().uextend(types::I64, a);
        b = bcx.ins().uextend(types::I64, b);
    }

    if ty == types::F32 || ty == types::F64 {
        return;
    }

    let loc = bcx.ins().iconst(types::I64, caller.as_u64() as i64);
    state.host_call(
        bcx,
        builtin_trace_cmp as unsafe extern "C" fn(_, _, _, _),
        &[a, b, loc],
    );
}

pub(crate) unsafe extern "C" fn builtin_trace_cmp(a: u64, b: u64, loc: u64, vmctx: *mut VMContext) { unsafe {
    if a == b {
        return;
    };
    if let Some(v) = values_to_cmplog(a, b) {
        let loc = Location::from_u64(loc);
        let loc_set = (*vmctx).feedback.cmplog.entry(loc).or_default();
        if loc_set.len() > 1000 {
            // Make sure that we won't run out of memory.
            // Can't handle so many I2S observations anyways...
            return;
        }
        loc_set.insert(v);
    }
}}

fn values_to_cmplog(a: u64, b: u64) -> Option<CmpLog> {
    if let (Ok(a), Ok(b)) = (a.try_into(), b.try_into()) {
        // we're handling u32-like values
        let _: (u32, u32) = (a, b);
        if i8::try_from(a as i32).is_ok() || i8::try_from(b as i32).is_ok() {
            // skip small integer comparisons
            return None;
        }

        if let (Ok(a), Ok(b)) = (a.try_into(), b.try_into()) {
            Some(CmpLog::U16(a, b))
        } else {
            Some(CmpLog::U32(a, b))
        }
    } else {
        // we're handling u64-like values
        if i8::try_from(a as i64).is_ok() || i8::try_from(b as i64).is_ok() {
            // skip small integer comparisons
            return None;
        }
        Some(CmpLog::U64(a, b))
    }
}

pub(crate) fn trace_memcmp(
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
    caller: Location,
    a: Value,
    b: Value,
    n: Value,
) {
    if state.dead(bcx) || state.options.kind != CompilationKind::Tracing {
        return;
    }

    let loc = bcx.ins().iconst(types::I64, caller.as_u64() as i64);
    state.host_call(
        bcx,
        builtin_trace_memcmp as unsafe extern "C" fn(_, _, _, _, _),
        &[a, b, n, loc],
    );
}

pub(crate) unsafe extern "C" fn builtin_trace_memcmp(
    a: u32,
    b: u32,
    n: u32,
    loc: u64,
    vmctx: *mut VMContext,
) { unsafe {
    let loc = Location::from_u64(loc);
    let heap = (*vmctx).heap();
    let (a, b, n) = (a as usize, b as usize, n as usize);
    let (Some(a), Some(b)) = (heap.get(a..a + n), heap.get(b..b + n)) else {
        // ignore out-of-bounds pointers
        return;
    };
    if a == b {
        return;
    }
    (*vmctx)
        .feedback
        .cmplog
        .entry(loc)
        .or_default()
        .insert(CmpLog::Memcmp(a.to_vec(), b.to_vec()));
}}

pub(crate) fn trace_strcmp(
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
    caller: Location,
    a: Value,
    b: Value,
) {
    if state.dead(bcx) || state.options.kind != CompilationKind::Tracing {
        return;
    }

    let loc = bcx.ins().iconst(types::I64, caller.as_u64() as i64);
    state.host_call(
        bcx,
        builtin_trace_strcmp as unsafe extern "C" fn(_, _, _, _),
        &[a, b, loc],
    );
}

pub(crate) unsafe extern "C" fn builtin_trace_strcmp(
    a: u32,
    b: u32,
    loc: u64,
    vmctx: *mut VMContext,
) { unsafe {
    let (a, b) = (a as usize, b as usize);
    let loc = Location::from_u64(loc);
    let heap = (*vmctx).heap();
    if a + 1 >= heap.len() || b + 1 >= heap.len() {
        // ignore out-of-bounds pointers
        return;
    }
    let n = {
        let a_n = heap[a..].iter().position(|&x| x == 0).unwrap_or(0);
        let b_n = heap[b..].iter().position(|&x| x == 0).unwrap_or(0);
        a_n.min(b_n) + 1
    };
    let a = &heap[a..][..n];
    let b = &heap[b..][..n];
    if a == b {
        return;
    }
    (*vmctx)
        .feedback
        .cmplog
        .entry(loc)
        .or_default()
        .insert(CmpLog::Memcmp(a.to_vec(), b.to_vec()));
}}
