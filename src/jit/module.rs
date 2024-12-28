use crate::{instrumentation::Passes, HashMap, HashSet};
use std::{any::Any, sync::Arc};

use crate::{
    ir::{FuncSpec, InsnIdx, Location, ModuleSpec},
    AbortCode,
};
use codegen::ir::{self, UserFuncName};
use cranelift::module::{default_libcall_names, FuncId, Linkage, Module};
use cranelift::prelude::*;
use cranelift::{
    codegen::MachTrap,
    jit::{JITBuilder, JITModule},
};

use super::{instance::ModuleInstance, util::wasm2tys, vmcontext::VMContext, CompilationOptions};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TrapKind {
    Coverage { location: Location, pass: String },
    Abort(AbortCode),
    SwarmShortCircuit(Location),
    OutOfFuel(Option<Location>),
    MemoryOutOfBounds,
    ExitTestcase(Location),
}

impl TrapKind {
    pub(crate) fn loc(&self) -> Option<Location> {
        match self {
            Self::MemoryOutOfBounds | Self::Abort(_) => None,
            Self::SwarmShortCircuit(loc) | Self::ExitTestcase(loc) => Some(*loc),
            Self::Coverage { location, .. } => Some(*location),
            Self::OutOfFuel(loc) => *loc,
        }
    }

    pub(crate) fn display(&self, spec: &ModuleSpec) -> String {
        use colored::Colorize;
        let name = match self {
            Self::Abort(AbortCode::UnreachableReached) => "abort-unreachable".red(),
            Self::Abort(_) => "abort/unk".red(),
            Self::MemoryOutOfBounds => "abort/mem-oob".red(),
            Self::SwarmShortCircuit(_) => "swarm-short-circuit".green(),
            Self::OutOfFuel(_) => "out-of-fuel".cyan(),
            Self::ExitTestcase(_) => "exit-testcase".cyan(),
            Self::Coverage { pass, .. } => pass.cyan(),
        };
        self.loc().map_or_else(
            || format!("trap/{name}"),
            |loc| {
                let loc = spec.format_location(loc);
                format!("trap/{name} @ {loc}")
            },
        )
    }

    // Does this trap correspond to a "fast exit"?
    // These don't indicate new coverage.
    pub(crate) fn is_short_circuit(&self) -> bool {
        matches!(
            self,
            Self::OutOfFuel(_) | Self::ExitTestcase(_) | Self::SwarmShortCircuit(_)
        )
    }

    pub(crate) fn is_crash(&self) -> bool {
        matches!(self, Self::Abort(_))
    }

    pub(crate) fn is_coverage_trap(&self) -> bool {
        !self.is_short_circuit() && !self.is_crash()
    }
}

fn isa() -> Arc<dyn isa::TargetIsa> {
    let mut flag_builder = settings::builder();

    flag_builder.set("is_pic", "true").unwrap();

    // --set opt_level=speed_and_size --set enable_heap_access_spectre_mitigation=false
    flag_builder.set("opt_level", "speed_and_size").unwrap();
    flag_builder
        .set("enable_heap_access_spectre_mitigation", "false")
        .unwrap();

    // we're not linking __cranelift_probestack, and stack clashing is not an issue
    flag_builder.set("enable_probestack", "false").unwrap();

    if !cfg!(debug_assertions)
        && !std::env::var("CRANELIFT_VERIFIER")
            .map(|el| el == "1")
            .unwrap_or_default()
    {
        flag_builder.set("enable_verifier", "false").unwrap();
        flag_builder.set("unwind_info", "false").unwrap();
    }

    let isa_builder = cranelift::native::builder().unwrap_or_else(|msg| {
        panic!("host machine is not supported: {msg}");
    });
    isa_builder
        .finish(settings::Flags::new(flag_builder))
        .unwrap()
}

struct FunctionArtifacts {
    func_code_size: usize,
    fidx: u32,
    trap_sinks: Vec<codegen::MachTrap>,
    trap_kinds: Vec<TrapKind>,
}

pub(crate) struct ModuleTranslator<'s> {
    pub vmctx: Box<VMContext>,
    pub spec: &'s ModuleSpec,
    pub func_ids: HashMap<u32, FuncId>,
    pub func_sigs: HashMap<u32, Signature>,
    pub module: JITModule,
    pub options: CompilationOptions,
}

impl<'s> ModuleTranslator<'s> {
    pub(crate) fn new(spec: &'s ModuleSpec, opts: &CompilationOptions) -> Self {
        let mut builder = JITBuilder::with_isa(isa(), default_libcall_names());
        builder.reserve_memory_area(256 << 20);
        let mut module = JITModule::new(builder);

        let mut func_ids = HashMap::default();
        let mut func_sigs = HashMap::default();
        for func in &spec.functions {
            let signature = Self::function_signature(&module, func, true, opts.is_concolic());
            let func_id = module
                .declare_function(&func.symbol, Linkage::Local, &signature)
                .unwrap();
            func_ids.insert(func.idx, func_id);
            func_sigs.insert(func.idx, signature);
        }

        ModuleTranslator {
            spec,
            vmctx: VMContext::new(spec),
            func_ids,
            func_sigs,
            module,
            options: opts.clone(),
        }
    }

    fn function_signature(
        module: &JITModule,
        func: &FuncSpec,
        internal: bool,
        with_concolic: bool,
    ) -> Signature {
        let mut signature = module.make_signature();
        if internal {
            signature.call_conv = isa::CallConv::Fast;
        }

        for param in func.ty.params() {
            signature.params.push(AbiParam::new(super::wasm2ty(param)));
        }

        for ret in func.ty.results() {
            signature.returns.push(AbiParam::new(super::wasm2ty(ret)));
        }

        if with_concolic && internal {
            let symval = AbiParam::new(ir::types::I32);
            for _ in func.ty.params() {
                signature.params.push(symval);
            }

            for _ in func.ty.results() {
                signature.returns.push(symval);
            }
        }

        signature.params.push(ir::AbiParam::special(
            module.target_config().pointer_type(),
            ir::ArgumentPurpose::VMContext,
        ));

        signature
    }

    fn subfuncs(func: &FuncSpec, func_ids: &HashMap<u32, FuncId>) -> HashSet<FuncId> {
        func.operators
            .iter()
            .flat_map(|op| match op {
                crate::ir::WFOperator::Control(crate::ir::ControlInstruction::Call {
                    function_index,
                    ..
                }) => Some(func_ids[function_index]),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn compile_to_instance(mut self, passes: &mut Passes) -> ModuleInstance {
        tracyrs::zone!("ModTrans::compile_to_instance");
        let spec = self.spec;
        let options = self.options.clone();
        let mut pass_meta = HashMap::default();

        let mut func_ctx = FunctionBuilderContext::new();
        let mut ctx = self.module.make_context();
        let mut trap_sinks = Vec::new();
        let mut code_size = 0;

        for func in &spec.functions {
            let FunctionArtifacts {
                func_code_size,
                fidx,
                trap_sinks: trap_sinks_,
                trap_kinds,
            } = Self::emit_function(
                func,
                &mut ctx,
                &mut func_ctx,
                spec,
                &options,
                passes,
                &mut self.module,
                &mut self.vmctx,
                &self.func_ids,
                &self.func_sigs,
                &mut pass_meta,
            );

            trap_sinks.push((self.func_ids[&fidx], trap_sinks_, trap_kinds));
            code_size += func_code_size;
        }

        let mut export_func_ids = HashMap::default();
        let mut exported_funcs: Vec<_> = spec.exported_funcs.iter().collect();
        exported_funcs.sort_by_key(|(_, fidx)| **fidx);
        for (symbol, &fidx) in exported_funcs {
            let res = self.emit_export_trampoline(
                spec,
                fidx,
                &options,
                symbol,
                &mut export_func_ids,
                &mut ctx,
                &mut func_ctx,
                &mut code_size,
                passes,
                &mut pass_meta,
            );
            trap_sinks.push(res);
        }

        // Perform linking.
        self.module
            .finalize_definitions()
            .expect("failed to finalize definition");

        for (tablei, (table, offset)) in spec.scuffed_func_table_initializers.iter().enumerate() {
            for (i, f) in table.iter().enumerate() {
                let ptr = self.module.get_finalized_function(self.func_ids[f]);
                self.vmctx.tables[tablei][i + *offset] = ptr as usize;
            }
        }

        let mut trap_pc_registry = HashMap::default();
        for (func_id, traps, trapcodes) in trap_sinks {
            let func_ptr = self.module.get_finalized_function(func_id) as usize;
            for trap in traps {
                let ptr = func_ptr + trap.offset as usize;
                use TrapCode as TC;
                use TrapKind as TK;
                let trap = match trap.code {
                    TC::STACK_OVERFLOW => TK::Abort(AbortCode::StackOverflow),
                    TC::HEAP_OUT_OF_BOUNDS => TK::Abort(AbortCode::HeapOutOfBounds),
                    TC::INTEGER_OVERFLOW => TK::Abort(AbortCode::IntegerOverflow),
                    TC::INTEGER_DIVISION_BY_ZERO => TK::Abort(AbortCode::IntegerDivisionByZero),
                    TC::BAD_CONVERSION_TO_INTEGER => TK::Abort(AbortCode::BadConversionToInteger),
                    _ => {
                        assert!(!TC::non_user_traps().contains(&trap.code));
                        trapcodes[trap.code.as_raw().get() as usize - 1].clone()
                    }
                };
                trap_pc_registry.insert(ptr, trap);
            }
        }

        let export_func_ptrs = export_func_ids
            .into_iter()
            .map(|(k, fid)| (k, self.module.get_finalized_function(fid)))
            .collect();

        self.vmctx.finalize();
        let s = self;
        ModuleInstance::new(
            s.vmctx,
            s.module,
            export_func_ptrs,
            trap_pc_registry,
            code_size,
            s.options,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_function(
        func: &FuncSpec,
        ctx: &mut codegen::Context,
        func_ctx: &mut FunctionBuilderContext,
        spec: &ModuleSpec,
        options: &CompilationOptions,
        passes: &mut Passes,
        module: &mut JITModule,
        vmctx: &mut VMContext,
        func_ids: &HashMap<u32, FuncId>,
        func_sigs: &HashMap<u32, Signature>,
        pass_meta: &mut HashMap<u64, Box<dyn Any>>,
    ) -> FunctionArtifacts {
        tracyrs::zone!("ModTrans::emit_function");
        let func_id = func_ids[&func.idx];

        ctx.func.signature = func_sigs[&func.idx].clone();
        ctx.func.name = UserFuncName::user(0, func.idx);
        let subfuncs = Self::subfuncs(func, func_ids);
        let mut bcx: FunctionBuilder = FunctionBuilder::new(&mut ctx.func, func_ctx);
        let func_refs = subfuncs
            .iter()
            .map(|func_id| {
                let funcref = module.declare_func_in_func(*func_id, bcx.func);
                (*func_id, funcref)
            })
            .collect::<HashMap<_, _>>();

        let mut functrans = super::FuncTranslator::new(
            vmctx, func_ids, spec, func.idx, func_refs, options, passes, module, pass_meta,
        );

        let loc = Location {
            function: func.idx,
            index: 0,
        };

        let block = bcx.create_block();
        bcx.switch_to_block(block);
        bcx.append_block_params_for_function_params(block);
        let params = bcx.block_params(block).to_vec();
        // populate parameters as locals
        for (i, ty) in func.ty.params().iter().enumerate() {
            let param = params[i];
            let var = functrans.get_slot(i as u32);
            bcx.declare_var(var, super::wasm2ty(ty));
            bcx.def_var(var, param);

            if functrans.options.is_concolic() {
                let var_sym = functrans.get_slot_concolic(i as u32);
                bcx.declare_var(var_sym, types::I32);
                bcx.def_var(var_sym, params[func.ty.params().len() + i]);
            }
        }
        // populate other locals with zeroed values
        for (ii, ty) in func.locals.iter().enumerate() {
            let i = func.ty.params().len() + ii;
            let val = crate::ir::Value::default_for_ty(ty);
            let (_, val) = super::numeric::translate_const(&val, &mut bcx);
            let var = functrans.get_slot(i as u32);
            bcx.declare_var(var, super::wasm2ty(ty));
            bcx.def_var(var, val);

            if functrans.options.is_concolic() {
                let var_sym = functrans.get_slot_concolic(i as u32);
                bcx.declare_var(var_sym, types::I32);
                let concrete = bcx.ins().iconst(types::I32, 0);
                bcx.def_var(var_sym, concrete);
            }
        }

        if options.verbose {
            println!("/ {}", func.symbol);
        }

        if options.debug_trace {
            super::builtins::translate_debug_log(
                format!(
                    "entering {} ({})",
                    func.symbol,
                    options.shortcode(functrans.passes.as_ref().unwrap())
                ),
                &mut functrans,
                &mut bcx,
            );
        }

        functrans.iter_passes(&mut bcx, |pass, ctx| pass.instrument_function(ctx));
        super::instrumentation::instrument_func(&mut functrans, &mut bcx, loc);

        let dead = functrans.dead(&bcx);
        if functrans.dead(&bcx) {
            if options.verbose {
                println!("{} <dead>", func.symbol);
            }
        } else {
            for (ip, op) in func.operators.iter().enumerate() {
                functrans.translate_op(op, &mut bcx, InsnIdx(ip as u32));
            }
            if options.verbose {
                println!("\\ {:?}", func.ty);
            }
        }
        functrans.iter_passes(&mut bcx, |pass, ctx| pass.instrument_function_ret(ctx));

        let returns = wasm2tys(func.ty.results());
        if !functrans.dead(&bcx) {
            let mut rvals = functrans.popn(&returns, &mut bcx);
            if functrans.options.is_concolic() {
                let concolic_vars = rvals
                    .iter()
                    .map(|el| functrans.get_concolic(el))
                    .collect::<Vec<_>>();
                rvals.extend_from_slice(&concolic_vars);
            }

            if options.debug_trace {
                super::builtins::translate_debug_log(
                    format!("returning from {} via function end", func.symbol),
                    &mut functrans,
                    &mut bcx,
                );
            }
            bcx.ins().return_(&rvals);
            functrans.mark_dead(&mut bcx);
        }

        bcx.seal_all_blocks();
        bcx.finalize();

        if options.verbose && !dead {
            println!(
                "> {} [{}]",
                func.symbol,
                options.shortcode(functrans.passes.as_ref().unwrap())
            );
            println!("{}", ctx.func.display());
        }

        let super::FuncTranslator { trapcodes, .. } = functrans;

        ctx.set_disasm(options.verbose && !dead);

        module
            .define_function(func_id, ctx)
            .expect("couldn't compile function");

        let compiled_code = ctx.compiled_code().unwrap();
        let disasm = compiled_code.vcode.as_ref();
        if let Some(disasm) = &disasm {
            println!("{disasm}");
        }

        let traps = compiled_code.buffer.traps().to_vec();
        let func_code_size = compiled_code.code_info().total_size as usize;

        module.clear_context(ctx);

        FunctionArtifacts {
            func_code_size,
            fidx: func.idx,
            trap_sinks: traps,
            trap_kinds: trapcodes,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_export_trampoline(
        &mut self,
        spec: &ModuleSpec,
        fidx: u32,
        options: &CompilationOptions,
        symbol: &str,
        export_func_ids: &mut HashMap<String, FuncId>,
        ctx: &mut codegen::Context,
        func_ctx: &mut FunctionBuilderContext,
        code_size: &mut usize,
        passes: &mut Passes,
        pass_meta: &mut HashMap<u64, Box<dyn Any>>,
    ) -> (FuncId, Vec<MachTrap>, Vec<TrapKind>) {
        let func = &spec.functions[fidx as usize];
        let signature = Self::function_signature(&self.module, func, false, options.is_concolic());
        let export_func_id = self
            .module
            .declare_function(symbol, Linkage::Local, &signature)
            .unwrap();
        export_func_ids.insert(symbol.to_owned(), export_func_id);
        ctx.func.signature = Self::function_signature(&self.module, func, false, false);
        assert!(ctx.func.signature.call_conv == isa::CallConv::SystemV);
        ctx.func.name = UserFuncName::user(1, func.idx);
        let subfunc_id = self.func_ids[&func.idx];
        let mut bcx: FunctionBuilder = FunctionBuilder::new(&mut ctx.func, func_ctx);
        let subfunc_ref = self.module.declare_func_in_func(subfunc_id, bcx.func);
        let block = bcx.create_block();
        bcx.switch_to_block(block);
        bcx.append_block_params_for_function_params(block);
        let mut params = bcx.block_params(block).to_vec();
        if options.is_concolic() {
            let vmctx = params.pop().unwrap();
            let sym_concrete = bcx.ins().iconst(types::I32, 0);
            params.extend(vec![sym_concrete; func.ty.params().len()]);
            params.push(vmctx);
        }

        let _func_ids = HashMap::default();
        let mut tramp_functrans = super::FuncTranslator::new(
            &mut self.vmctx,
            &_func_ids,
            spec,
            func.idx,
            HashMap::default(),
            options,
            passes,
            &mut self.module,
            pass_meta,
        );
        tramp_functrans.iter_passes(&mut bcx, |pass, ctx| pass.instrument_trampoline(ctx));
        if symbol == "LLVMFuzzerTestOneInput" {
            assert_eq!(func.ty.params().len(), 2);
            let inp_ptr = params[0];
            let inp_len = params[1];
            tramp_functrans.iter_passes(&mut bcx, |pass, ctx| {
                pass.instrument_fuzz_trampoline(inp_ptr, inp_len, ctx)
            });
        }

        let call_inst = bcx.ins().call(subfunc_ref, &params);
        let mut rvals = bcx.inst_results(call_inst).to_vec();
        if options.is_concolic() {
            rvals.truncate(func.ty.results().len());
        }

        tramp_functrans.iter_passes(&mut bcx, |pass, ctx| pass.instrument_trampoline_ret(ctx));

        let super::FuncTranslator { trapcodes, .. } = tramp_functrans;

        bcx.ins().return_(&rvals);
        bcx.seal_block(block);
        bcx.finalize();
        if options.verbose {
            println!("> export/{}", func.symbol);
            println!("{}", ctx.func.display());
        }
        ctx.set_disasm(options.verbose);
        self.module
            .define_function(export_func_id, ctx)
            .expect("couldn't compile function");
        let compiled_code = ctx.compiled_code().unwrap();
        if let Some(disasm) = &compiled_code.vcode {
            println!("{disasm}");
        }
        *code_size += compiled_code.code_info().total_size as usize;
        let traps = compiled_code.buffer.traps().to_vec();
        self.module.clear_context(ctx);

        (export_func_id, traps, trapcodes)
    }
}
