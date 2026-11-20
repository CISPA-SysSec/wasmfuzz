use codegen::ir;
use cranelift::codegen::isa::CallConv;
use cranelift::prelude::*;

use super::signals::{TrapReason, raise_trap};

use super::{FuncTranslator, vmcontext::VMContext};

/// Fuel charged for a `memory.fill` / `memory.copy` of `len` bytes: one unit per 4 bytes, plus one
/// for the operation itself. A fill or copy of resident memory costs about 0.08-0.25 cycles per
/// byte and executed code about 0.6 cycles per fuel unit, so this keeps the cost of bulk memory in
/// line with that of executed code.
pub(crate) const fn bulk_memory_fuel(len: u32) -> u64 {
    len as u64 / 4 + 1
}

thread_local! {
    /// Fuel charged by the bulk-memory builtins (memory.fill / memory.copy, see `bulk_memory_fuel`)
    /// on this thread. Diagnostic only: `fuel-census` reads it to show how much of an input's fuel
    /// is bulk memory rather than executed code. Thread-local so fuzzing threads never share a
    /// cache line.
    pub(crate) static BULK_FUEL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

pub(crate) unsafe extern "C" fn builtin_memory_size(vmctx: *mut VMContext) -> u32 {
    unsafe { (*vmctx).heap_pages }
}

pub(crate) unsafe extern "C" fn builtin_memory_grow(delta: u32, vmctx: *mut VMContext) -> u32 {
    unsafe {
        let vmctx = &mut *vmctx;
        let new_pages = vmctx.heap_pages.saturating_add(delta);
        // growing past the module-declared max fails (-1) without trapping
        if new_pages > vmctx.heap_pages_limit_module {
            return u32::MAX;
        }
        if new_pages > vmctx.heap_pages_limit_hard {
            println!(
                "builtin_memory_grow({}) exceeds hard limit. current_size={}",
                delta, vmctx.heap_pages
            );
            return u32::MAX;
        }
        if new_pages > vmctx.heap_pages_limit_soft {
            raise_trap(TrapReason::OutOfMemory);
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
}

pub(crate) unsafe extern "C" fn builtin_memory_fill(
    dest: u32,
    val: u32,
    len: u32,
    vmctx: *mut VMContext,
) {
    unsafe {
        let vmctx = &mut *vmctx;
        let fuel = bulk_memory_fuel(len);
        BULK_FUEL.with(|c| c.set(c.get() + fuel));
        vmctx.builtin_consume_fuel(fuel);

        if vmctx
            .heap_fill(dest as usize, len as usize, val as u8)
            .is_none()
        {
            raise_trap(TrapReason::MemoryOutOfBounds)
        }
    }
}

pub(crate) unsafe extern "C" fn builtin_memory_copy(
    dst_pos: u32,
    src_pos: u32,
    len: u32,
    vmctx: *mut VMContext,
) {
    unsafe {
        let vmctx = &mut *vmctx;
        let fuel = bulk_memory_fuel(len);
        BULK_FUEL.with(|c| c.set(c.get() + fuel));
        vmctx.builtin_consume_fuel(fuel);
        let heap = vmctx.heap();

        let (dst_pos, src_pos, len) = (dst_pos as usize, src_pos as usize, len as usize);

        let (Some(_dst), Some(_src)) = (
            heap.get(dst_pos..dst_pos + len),
            heap.get(src_pos..src_pos + len),
        ) else {
            raise_trap(TrapReason::MemoryOutOfBounds)
        };

        // after the bounds check, so a trapping copy doesn't mark pages it
        // never got to write
        vmctx.mark_heap_dirty(dst_pos, len);
        vmctx.heap().copy_within(src_pos..(src_pos + len), dst_pos);
    }
}

pub(crate) unsafe extern "C" fn builtin_random_get(dest: u32, len: u32, vmctx: *mut VMContext) {
    unsafe {
        let vmctx = &mut *vmctx;
        vmctx.builtin_consume_fuel(len as u64);
        use libafl_bolts::rands::{Rand, XorShift64Rand};
        let mut rng = XorShift64Rand::with_seed(vmctx.random_get_seed);
        vmctx.random_get_seed = rng.next();
        let Some(buf) = vmctx.heap_mut(dest as usize, len as usize) else {
            raise_trap(TrapReason::MemoryOutOfBounds)
        };
        for chunk in buf.chunks_mut(8) {
            let bytes = rng.next().to_ne_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

pub(crate) unsafe extern "C" fn builtin_clock_time_get(time_ptr: u32, vmctx: *mut VMContext) {
    unsafe {
        let vmctx = &mut *vmctx;
        vmctx.builtin_consume_fuel(1);
        let time = vmctx.fuel_init.saturating_sub(vmctx.fuel);
        // dbg!(vmctx.fuel_init, vmctx.fuel, time);
        // dbg!(time);
        let time = 1700000000 * 1000000000 + time * 100; // use a somewhat sensible time in nanos
        let Some(buf) = vmctx.heap_mut(time_ptr as usize, 8) else {
            raise_trap(TrapReason::MemoryOutOfBounds)
        };
        buf.copy_from_slice(&time.to_le_bytes());
    }
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
    // `special_param` reads the entry block; Cranelift only inserts a block
    // into the layout once it has an instruction (or we force it).
    bcx.ensure_inserted_block();
    bcx.func
        .special_param(ir::ArgumentPurpose::VMContext)
        .expect("Missing vmctx parameter")
}

unsafe extern "C" fn builtin_debug_log(idx: u32, vmctx: *mut VMContext) {
    unsafe {
        let vmctx = &mut *vmctx;
        eprintln!("JIT-TRACE: {}", vmctx.debugstrs[idx as usize]);
    }
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
