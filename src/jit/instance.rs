use crate::{HashMap, jit::signals::TrapReason};

use super::signals::catch_traps;
use cranelift::jit::JITModule;

use super::{CompilationOptions, module::TrapKind, vmcontext::VMContext};

pub(crate) struct ModuleInstance {
    pub vmctx: Box<VMContext>,
    pub code_size: usize,
    module: Option<JITModule>,
    export_func_ptrs: HashMap<String, *const u8>,
    trap_pc_registry: HashMap<usize, TrapKind>,
    options: CompilationOptions,
}

impl ModuleInstance {
    pub(crate) fn new(
        vmctx: Box<VMContext>,
        module: JITModule,
        export_func_ptrs: HashMap<String, *const u8>,
        trap_pc_registry: HashMap<usize, TrapKind>,
        code_size: usize,
        options: CompilationOptions,
    ) -> Self {
        Self {
            vmctx,
            module: Some(module),
            export_func_ptrs,
            trap_pc_registry,
            code_size,
            options,
        }
    }

    pub(crate) unsafe fn get_export(&self, export: &str) -> *const u8 {
        *self
            .export_func_ptrs
            .get(export)
            .unwrap_or_else(|| panic!("export {export:?} not found"))
    }

    // TODO: Verify that ABI matches? ABI mismatches can be hard to track down!
    pub(crate) fn enter<R, F: Fn(*mut VMContext) -> R>(&mut self, f: F) -> Result<R, TrapKind> {
        tracy_full::zone!("ModuleInstance::enter");
        assert!(!self.vmctx.tainted);
        self.vmctx.fuel = self.vmctx.fuel_init;
        let vmctx_ptr = (&mut *self.vmctx) as *mut VMContext;
        // Safety: closure shouldn't and doesn't capture any Drops
        //         vmctx_ptr needs to be valid and ABI should match
        let res = unsafe { catch_traps(|| f(vmctx_ptr)) };
        if res.is_err() {
            self.vmctx.tainted = true;
        }
        res.map_err(|info| match info.reason {
            Some(TrapReason::MemoryOutOfBounds) => {
                TrapKind::Abort(crate::AbortCode::HeapOutOfBounds)
            }
            Some(TrapReason::OutOfFuel) => TrapKind::OutOfFuel(None),
            Some(TrapReason::OutOfMemory) => TrapKind::OutOfMemory(None),
            None => {
                let pc = info.pc;
                let faulting_addr = info.faulting_addr;
                let Some(trap) = self.trap_pc_registry.get(&pc) else {
                    let pos = self.vmctx.input_ptr as usize;
                    let len = self.vmctx.input_size;
                    let buf = &self.vmctx.heap()[pos..pos + len];
                    std::fs::write("/tmp/input.bin", buf).unwrap();
                    panic!("trapped at unknown pc {pc:#x} faulting_addr={faulting_addr:?}")
                };
                trap.clone()
            }
        })
    }

    // TODO(perf): mutate directly in the instance's memory to avoid write_input call?
    pub(crate) fn write_input(&mut self, pos: usize, buf: &[u8]) {
        tracy_full::zone!("ModuleInstance::write_input");
        // std::fs::write("/tmp/input.bin", buf);
        self.vmctx.input_ptr = pos as u32;
        self.vmctx.input_size = buf.len();

        if cfg!(feature = "concolic_debug_verify") {
            self.vmctx.input.clear();
            self.vmctx.input.extend_from_slice(buf);
        }
        // unstable feedback might be caused by input buffer over-reads
        // self.vmctx.heap()[pos..][..u16::MAX as usize].fill(0);
        self.vmctx.heap()[pos..pos + buf.len()].copy_from_slice(buf);

        if self.options.is_concolic() {
            self.vmctx.concolic.mark_input(pos, buf.len());
        }
    }
}

impl Drop for ModuleInstance {
    fn drop(&mut self) {
        tracy_full::zone!("ModuleInstance::drop");
        if let Some(module) = std::mem::take(&mut self.module) {
            unsafe { module.free_memory() };
        }
    }
}
