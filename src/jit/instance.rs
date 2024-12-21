use crate::{ir::Location, HashMap};

use cranelift::jit::JITModule;
use wasmtime::vm::{catch_traps, TrapReason};

use super::{module::TrapKind, vmcontext::VMContext, CompilationOptions};

pub(crate) struct ModuleInstance {
    pub vmctx: Box<VMContext>,
    pub code_size: usize,
    #[allow(unused)]
    module: JITModule,
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
        // NB: The trap we're returning in get_wasm_trap here is arbitrary.
        // We're resolving traps separately based on trap pc address.
        wasmtime::vm::init_traps(|_| Some(wasmtime::Trap::AlwaysTrapAdapter), true); // (crate::module::GlobalModuleRegistry::is_wasm_pc);
        Self {
            vmctx,
            module,
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
        tracyrs::zone!("ModuleInstance::enter");
        assert!(!self.vmctx.tainted);
        self.vmctx.fuel = self.vmctx.fuel_init;
        let mut res = None;
        let res_ref = &mut res;
        let vmctx_ptr = (&mut *self.vmctx) as *mut VMContext;
        let signal_handler = None;
        let callee = std::ptr::null_mut(); // We're not using wasmtime's VMContexts
        let runtime_res = unsafe {
            // Safety: closure shouldn't and doesn't capture any Drops
            //         vmctx_ptr needs to be valid and ABI should match
            catch_traps(signal_handler, false, false, callee, |_| {
                *res_ref = Some(f(vmctx_ptr));
            })
        };
        match runtime_res {
            Ok(()) => Ok(res.unwrap()),
            Err(trap) => match trap.reason {
                TrapReason::Jit {
                    pc,
                    faulting_addr,
                    trap: _,
                } => {
                    let Some(trap) = self.trap_pc_registry.get(&pc) else {
                        let pos = self.vmctx.input_ptr as usize;
                        let len = self.vmctx.input_size;
                        let buf = &self.vmctx.heap()[pos..pos + len];
                        std::fs::write("/tmp/input.bin", buf).unwrap();
                        panic!("trapped at unknown pc {pc:#x} faulting_addr={faulting_addr:?}")
                    };
                    self.vmctx.tainted = true;
                    Err(trap.clone())
                }
                TrapReason::Wasm(wasmtime::Trap::OutOfFuel) => {
                    self.vmctx.tainted = true;
                    Err(TrapKind::OutOfFuel(Location {
                        function: 0,
                        index: 0,
                    }))
                }
                _ => panic!("unexpected trap: {trap:?}"),
            },
        }
    }

    // TODO(perf): mutate directly in the instance's memory to avoid write_input call?
    pub(crate) fn write_input(&mut self, pos: usize, buf: &[u8]) {
        tracyrs::zone!("ModuleInstance::write_input");
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
