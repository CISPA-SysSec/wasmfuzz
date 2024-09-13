use codegen::ir;
use cranelift::codegen::isa::CallConv;
use cranelift::prelude::*;
use wasmtime::vm::{raise_trap, TrapReason};

use super::{vmcontext::VMContext, FuncTranslator};

pub(crate) unsafe extern "C" fn builtin_memory_size(vmctx: *mut VMContext) -> u32 {
    (*vmctx).heap_pages
}

pub(crate) unsafe extern "C" fn builtin_memory_grow(delta: u32, vmctx: *mut VMContext) -> u32 {
    let vmctx = &mut *vmctx;
    if vmctx.heap_pages.saturating_add(delta) > vmctx.heap_pages_limit_hard {
        println!(
            "builtin_memory_grow({}) exceeds hard limit. current_size={}",
            delta, vmctx.heap_pages
        );
        // raise_trap(TrapReason::Wasm(wasmtime::Trap::StackOverflow));
        return u32::MAX;
    }
    if vmctx.heap_pages.saturating_add(delta) > vmctx.heap_pages_limit_soft {
        raise_trap(TrapReason::Wasm(wasmtime::Trap::OutOfFuel));
    }
    vmctx.builtin_consume_fuel(delta as u64);
    let old = vmctx.heap_pages;
    vmctx.heap_pages += delta;
    let byte_len = (vmctx.heap_pages as usize) << 16;
    if vmctx.heap_alloc.as_slice().len() < byte_len {
        vmctx.heap_alloc.resize(byte_len);
    }
    old
}

pub(crate) unsafe extern "C" fn builtin_memory_fill(
    dest: u32,
    val: u32,
    len: u32,
    vmctx: *mut VMContext,
) {
    let vmctx = &mut *vmctx;
    vmctx.builtin_consume_fuel(len as u64);

    let Some(buf) = vmctx
        .heap()
        .get_mut(dest as usize..dest as usize + len as usize)
    else {
        raise_trap(TrapReason::Wasm(wasmtime::Trap::MemoryOutOfBounds));
    };

    buf.fill(val as u8);
}

pub(crate) unsafe extern "C" fn builtin_memory_copy(
    dst_pos: u32,
    src_pos: u32,
    len: u32,
    vmctx: *mut VMContext,
) {
    let vmctx = &mut *vmctx;
    vmctx.builtin_consume_fuel(len as u64);
    let heap = vmctx.heap();

    let (dst_pos, src_pos, len) = (dst_pos as usize, src_pos as usize, len as usize);

    let (Some(_dst), Some(_src)) = (
        heap.get(dst_pos..dst_pos + len),
        heap.get(src_pos..src_pos + len),
    ) else {
        raise_trap(TrapReason::Wasm(wasmtime::Trap::MemoryOutOfBounds));
    };

    heap.copy_within(src_pos..(src_pos + len), dst_pos);
}

pub(crate) unsafe extern "C" fn builtin_random_get(dest: u32, len: u32, vmctx: *mut VMContext) {
    let vmctx = &mut *vmctx;
    vmctx.builtin_consume_fuel(len as u64);
    let mut rng = XorShift64Rand::with_seed(vmctx.random_get_seed);
    vmctx.random_get_seed = rng.next_u64();
    let Some(buf) = vmctx
        .heap()
        .get_mut(dest as usize..dest as usize + len as usize)
    else {
        raise_trap(TrapReason::Wasm(wasmtime::Trap::MemoryOutOfBounds));
    };
    use libafl_bolts::rands::XorShift64Rand;
    use rand::RngCore;
    rng.fill_bytes(buf);
}

pub(crate) fn signature(
    params: &[ir::types::Type],
    returns: &[ir::types::Type],
    with_vmctx: bool,
) -> Signature {
    let mut sig = Signature::new(CallConv::SystemV);
    for ty in params {
        sig.params.push(ir::AbiParam::new(*ty));
    }

    if with_vmctx {
        let ptr_ty = ir::types::I64;
        assert!(std::mem::size_of::<usize>() == 8);
        sig.params.push(ir::AbiParam::special(
            ptr_ty,
            ir::ArgumentPurpose::VMContext,
        ));
    }

    for ty in returns {
        sig.returns.push(ir::AbiParam::new(*ty));
    }

    sig
}

pub(crate) fn fetch_vmctx(bcx: &mut FunctionBuilder) -> Value {
    bcx.func
        .special_param(ir::ArgumentPurpose::VMContext)
        .expect("Missing vmctx parameter")
}

pub(crate) unsafe extern "C" fn builtin_trace_wasmfuzz_write_stdout(
    buf: u32,
    n: u32,
    vmctx: *mut VMContext,
) {
    let vmctx = &mut *vmctx;
    let buf = &vmctx.heap()[buf as usize..][..n as usize].to_vec();
    assert!(buf.len() == n as usize);
    if !buf.is_empty() {
        vmctx.feedback.stdout.extend_from_slice(buf);
    }
}

pub(crate) unsafe extern "C" fn builtin_debug_wasmfuzz_write_stdout(
    buf: u32,
    n: u32,
    vmctx: *mut VMContext,
) {
    let vmctx = &mut *vmctx;
    let buf = &vmctx.heap()[buf as usize..][..n as usize].to_vec();
    assert!(buf.len() == n as usize);
    if !buf.is_empty() {
        dbg!(String::from_utf8_lossy(buf));
    }
}

unsafe extern "C" fn builtin_debug_log(idx: u32, vmctx: *mut VMContext) {
    let vmctx = &mut *vmctx;
    eprintln!("JIT-TRACE: {}", vmctx.debugstrs[idx as usize]);
}

pub(crate) fn translate_debug_log(
    s: String,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    if state.dead(bcx) {
        return;
    }
    let idx = {
        let idx = state.vmctx.debugstrs.len();
        state.vmctx.debugstrs.push(s);
        idx
    };

    let idx = bcx.ins().iconst(types::I32, idx as i64);
    state.host_call(bcx, builtin_debug_log as unsafe extern "C" fn(_, _), &[idx]);
}
