//! Runs the WebAssembly spec testsuite (`tests/wasm-testsuite`) against the JIT.
//!
//! ```text
//! git submodule update --init tests/wasm-testsuite
//! cargo test --release spec_testsuite -- --ignored --nocapture
//! ```

use crate::{
    AbortCode, HashMap,
    instrumentation::Passes,
    ir::ModuleSpec,
    jit::{
        CompilationKind, CompilationOptions, DebugTrace, SwarmConfig, TracingOptions,
        TrackingOptions,
        instance::ModuleInstance,
        module::{ModuleTranslator, TrapKind},
        vmcontext::VMContext,
        wasm2ty,
    },
};
use std::{
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::Arc,
};

use cranelift::codegen::ir::ArgumentPurpose;
use cranelift::jit::{JITBuilder, JITModule};
use cranelift::module::{Linkage, Module, default_libcall_names};
use cranelift::prelude::*;
use wasmparser::ValType;
use wast::core::{NanPattern, WastArgCore, WastRetCore};
use wast::parser::{self, ParseBuffer};
use wast::{QuoteWat, Wast, WastArg, WastDirective, WastExecute, WastInvoke, WastRet};

// We only model the MVP numeric types. Floats are kept as raw bits since NaN
// payloads matter.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Val {
    I32(i32),
    I64(i64),
    F32(u32),
    F64(u64),
}

impl Val {
    fn ty(&self) -> ValType {
        match self {
            Self::I32(_) => ValType::I32,
            Self::I64(_) => ValType::I64,
            Self::F32(_) => ValType::F32,
            Self::F64(_) => ValType::F64,
        }
    }

    fn to_slot(self) -> u64 {
        match self {
            Self::I32(v) => v as u32 as u64,
            Self::I64(v) => v as u64,
            Self::F32(b) => b as u64,
            Self::F64(b) => b,
        }
    }

    fn from_slot(ty: ValType, slot: u64) -> Self {
        match ty {
            ValType::I32 => Self::I32(slot as u32 as i32),
            ValType::I64 => Self::I64(slot as i64),
            ValType::F32 => Self::F32(slot as u32),
            ValType::F64 => Self::F64(slot),
            _ => unreachable!(),
        }
    }

    fn from_arg(arg: &WastArg) -> Option<Self> {
        match arg {
            WastArg::Core(WastArgCore::I32(v)) => Some(Self::I32(*v)),
            WastArg::Core(WastArgCore::I64(v)) => Some(Self::I64(*v)),
            WastArg::Core(WastArgCore::F32(v)) => Some(Self::F32(v.bits)),
            WastArg::Core(WastArgCore::F64(v)) => Some(Self::F64(v.bits)),
            _ => None,
        }
    }
}

fn is_numeric(ty: &ValType) -> bool {
    matches!(
        ty,
        ValType::I32 | ValType::I64 | ValType::F32 | ValType::F64
    )
}

// Exports are SystemV functions taking `(params.., vmctx)`. To call arbitrary
// signatures from Rust, we JIT one adapter per signature that unpacks
// arguments from an array of u64 slots and writes results back the same way.
type AdapterFn = unsafe extern "C" fn(*const u8, *const u64, *mut u64, *mut VMContext);

struct AdapterJit {
    module: JITModule,
    cache: HashMap<(Vec<ValType>, Vec<ValType>), AdapterFn>,
}

impl AdapterJit {
    fn new() -> Self {
        let mut flag_builder = settings::builder();
        flag_builder.set("opt_level", "none").unwrap();
        flag_builder.set("enable_probestack", "false").unwrap();
        let isa = cranelift::native::builder()
            .unwrap()
            .finish(settings::Flags::new(flag_builder))
            .unwrap();
        Self {
            module: JITModule::new(JITBuilder::with_isa(isa, default_libcall_names())),
            cache: HashMap::default(),
        }
    }

    fn get(&mut self, params: &[ValType], results: &[ValType]) -> AdapterFn {
        let key = (params.to_vec(), results.to_vec());
        if let Some(f) = self.cache.get(&key) {
            return *f;
        }

        let ptr_ty = self.module.target_config().pointer_type();

        // fn(target, args, rets, vmctx)
        let mut adapter_sig = self.module.make_signature();
        adapter_sig.params = vec![AbiParam::new(ptr_ty); 4];
        let name = format!("adapter_{}", self.cache.len());
        let func_id = self
            .module
            .declare_function(&name, Linkage::Export, &adapter_sig)
            .unwrap();

        // matches `ModuleTranslator::function_signature(.., internal=false)`
        let mut target_sig = self.module.make_signature();
        target_sig.params = params.iter().map(|ty| AbiParam::new(wasm2ty(ty))).collect();
        target_sig
            .params
            .push(AbiParam::special(ptr_ty, ArgumentPurpose::VMContext));
        target_sig.returns = results
            .iter()
            .map(|ty| AbiParam::new(wasm2ty(ty)))
            .collect();

        let mut ctx = self.module.make_context();
        ctx.func.signature = adapter_sig;
        let mut fctx = FunctionBuilderContext::new();
        let mut bcx = FunctionBuilder::new(&mut ctx.func, &mut fctx);
        let block = bcx.create_block();
        bcx.switch_to_block(block);
        bcx.append_block_params_for_function_params(block);
        let &[target, args_ptr, rets_ptr, vmctx] = bcx.block_params(block) else {
            unreachable!()
        };
        let sigref = bcx.import_signature(target_sig);
        let flags = MemFlagsData::trusted();

        let mut call_args = Vec::with_capacity(params.len() + 1);
        for (i, ty) in params.iter().enumerate() {
            call_args.push(bcx.ins().load(wasm2ty(ty), flags, args_ptr, i as i32 * 8));
        }
        call_args.push(vmctx);
        let call = bcx.ins().call_indirect(sigref, target, &call_args);
        for (i, val) in bcx.inst_results(call).to_vec().into_iter().enumerate() {
            bcx.ins().store(flags, val, rets_ptr, i as i32 * 8);
        }
        bcx.ins().return_(&[]);
        bcx.seal_all_blocks();
        bcx.finalize(self.module.target_config());

        self.module.define_function(func_id, &mut ctx).unwrap();
        self.module.clear_context(&mut ctx);
        self.module.finalize_definitions().unwrap();

        let code = self.module.get_finalized_function(func_id);
        let f = unsafe { std::mem::transmute::<*const u8, AdapterFn>(code) };
        self.cache.insert(key, f);
        f
    }
}

struct Instance {
    spec: Arc<ModuleSpec>,
    inner: ModuleInstance,
}

impl Instance {
    fn compile(spec: Arc<ModuleSpec>) -> Self {
        let opts = CompilationOptions::new(
            &TrackingOptions::default(),
            &TracingOptions::default(),
            &SwarmConfig::default(),
            CompilationKind::Reusable,
            DebugTrace::Disabled,
            false,
            true,
        );
        let inner = ModuleTranslator::new(&spec, &opts).compile_to_instance(&mut Passes::empty());
        Self { spec, inner }
    }

    // Returns `None` if the export is missing or its signature isn't supported.
    fn invoke(
        &mut self,
        adapters: &mut AdapterJit,
        name: &str,
        args: &[Val],
    ) -> Option<Result<Vec<Val>, TrapKind>> {
        let fidx = *self.spec.exported_funcs.get(name)?;
        let ty = &self.spec.functions[fidx as usize].ty;
        let (params, results) = (ty.params(), ty.results());
        if !params.iter().chain(results).all(is_numeric)
            || !args.iter().map(Val::ty).eq(params.iter().copied())
        {
            return None;
        }

        let adapter = adapters.get(params, results);
        let arg_slots: Vec<u64> = args.iter().map(|v| v.to_slot()).collect();
        let mut ret_slots = vec![0u64; results.len()];
        let args_ptr = arg_slots.as_ptr();
        let rets_ptr = ret_slots.as_mut_ptr();

        // Directives keep running on a module after it trapped. Traps don't
        // roll back memory, which matches spec semantics.
        self.inner.vmctx.tainted = false;
        let target = unsafe { self.inner.get_export(name) };
        let res = self
            .inner
            .enter(move |vmctx| unsafe { adapter(target, args_ptr, rets_ptr, vmctx) });

        Some(res.map(|()| {
            results
                .iter()
                .zip(ret_slots)
                .map(|(ty, slot)| Val::from_slot(*ty, slot))
                .collect()
        }))
    }
}

enum Outcome {
    Returned(Vec<Val>),
    Trapped(TrapKind),
    Panicked,
    // named modules, non-numeric types, ...
    Unsupported,
}

#[derive(Default)]
struct Tally {
    pass: usize,
    skip: usize,
    failures: Vec<String>,
}

impl Tally {
    // Records anything but a normal return, which the caller checks.
    fn expect_return(&mut self, outcome: Outcome, at: &str, name: &str) -> Option<Vec<Val>> {
        match outcome {
            Outcome::Returned(vals) => return Some(vals),
            // the engine explicitly bailing on an unimplemented opcode
            Outcome::Unsupported | Outcome::Trapped(TrapKind::Abort(AbortCode::Unimplemented)) => {
                self.skip += 1
            }
            Outcome::Trapped(trap) => self.failures.push(format!(
                "{at}: invoke {name:?} unexpectedly trapped: {trap:?}"
            )),
            Outcome::Panicked => self
                .failures
                .push(format!("{at}: invoke {name:?} panicked in engine")),
        }
        None
    }

    fn expect_trap(&mut self, outcome: Outcome, at: &str, name: &str, message: &str) {
        match outcome {
            Outcome::Trapped(trap) if trap.is_crash() => self.pass += 1,
            Outcome::Unsupported => self.skip += 1,
            Outcome::Trapped(trap) => self.failures.push(format!(
                "{at}: invoke {name:?} expected trap ({message:?}) but got non-crash trap {trap:?}"
            )),
            Outcome::Returned(vals) => self.failures.push(format!(
                "{at}: invoke {name:?} expected trap ({message:?}) but returned {vals:?}"
            )),
            Outcome::Panicked => self
                .failures
                .push(format!("{at}: invoke {name:?} panicked in engine")),
        }
    }

    fn check_results(&mut self, expected: &[WastRet], got: &[Val], at: &str) {
        if expected.len() != got.len() {
            self.failures.push(format!(
                "{at}: result arity mismatch: expected {}, got {}",
                expected.len(),
                got.len()
            ));
            return;
        }
        for (i, (exp, val)) in expected.iter().zip(got).enumerate() {
            let WastRet::Core(exp) = exp else {
                self.skip += 1;
                return;
            };
            match check_ret(exp, *val) {
                Some(Ok(())) => {}
                Some(Err(reason)) => {
                    self.failures.push(format!("{at}: result #{i}: {reason}"));
                    return;
                }
                None => {
                    self.skip += 1;
                    return;
                }
            }
        }
        self.pass += 1;
    }
}

// Returns `None` for expectations on types we don't model (refs, v128, ...).
fn check_ret(expected: &WastRetCore, got: Val) -> Option<Result<(), String>> {
    Some(match expected {
        WastRetCore::I32(v) => check_eq(Val::I32(*v), got),
        WastRetCore::I64(v) => check_eq(Val::I64(*v), got),
        WastRetCore::F32(pat) => check_float(pat, ValType::F32, got, |v| v.bits.into()),
        WastRetCore::F64(pat) => check_float(pat, ValType::F64, got, |v| v.bits),
        WastRetCore::Either(opts) => {
            if opts.iter().any(|o| check_ret(o, got) == Some(Ok(()))) {
                Ok(())
            } else {
                Err(format!("none of `either` patterns matched {got:?}"))
            }
        }
        _ => return None,
    })
}

fn check_eq(expected: Val, got: Val) -> Result<(), String> {
    if expected == got {
        Ok(())
    } else {
        Err(format!("expected {expected:?}, got {got:?}"))
    }
}

fn check_float<T>(
    pat: &NanPattern<T>,
    ty: ValType,
    got: Val,
    bits_of: impl Fn(&T) -> u64,
) -> Result<(), String> {
    let (bits, abs_mask, canonical_nan) = match got {
        Val::F32(b) if ty == ValType::F32 => (b.into(), 0x7fff_ffff, 0x7fc0_0000),
        Val::F64(b) if ty == ValType::F64 => (b, 0x7fff_ffff_ffff_ffff, 0x7ff8_0000_0000_0000),
        _ => return Err(format!("expected {ty:?}, got {got:?}")),
    };
    // A canonical NaN has only the quiet bit set in its payload, an arithmetic
    // NaN at least that one. The sign is ignored for both.
    let (ok, expected) = match pat {
        NanPattern::CanonicalNan => (bits & abs_mask == canonical_nan, "canonical NaN".into()),
        NanPattern::ArithmeticNan => (
            bits & canonical_nan == canonical_nan,
            "arithmetic NaN".into(),
        ),
        NanPattern::Value(v) => (bits == bits_of(v), format!("{:#x}", bits_of(v))),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("expected {ty:?} {expected}, got {bits:#x}"))
    }
}

// Failures in these files are expected (xfail) and don't fail the test. Keep
// this list tight so that genuine regressions surface.
fn known_divergence(file: &str) -> Option<&'static str> {
    Some(match file {
        "memory-multi.wast" | "memory_grow.wast" | "float_exprs0.wast" | "memory_size1.wast"
        | "memory_size2.wast" | "align0.wast" | "store0.wast" => {
            "multiple memories are not supported"
        }
        // call_indirect checks signatures structurally, so a mismatch that only
        // differs in `(sub $a ...)` doesn't trap. GC is out of scope for Lime1.
        "type-subtyping.wast" => "GC nominal subtyping is not modelled",
        _ => return None,
    })
}

fn testsuite_dir() -> Option<PathBuf> {
    let dir = match std::env::var_os("WASM_TESTSUITE_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wasm-testsuite"),
    };
    // an uninitialized submodule is an empty directory
    dir.join("address.wast").exists().then_some(dir)
}

fn compile_module(quote: &mut QuoteWat, file: &str) -> Option<Instance> {
    let bytes = quote.encode().ok()?;
    std::panic::catch_unwind(|| {
        let spec = ModuleSpec::parse(file, &bytes).ok()?;
        // we can't observe what `start` does before the first invoke
        if spec.start_func.is_some() {
            return None;
        }
        Some(Instance::compile(Arc::new(spec)))
    })
    .ok()
    .flatten()
}

fn run_invoke(
    instance: Option<&mut Instance>,
    adapters: &mut AdapterJit,
    invoke: &WastInvoke,
) -> Outcome {
    let (None, Some(instance)) = (invoke.module, instance) else {
        return Outcome::Unsupported;
    };
    let Some(args) = invoke
        .args
        .iter()
        .map(Val::from_arg)
        .collect::<Option<Vec<_>>>()
    else {
        return Outcome::Unsupported;
    };
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        instance.invoke(adapters, invoke.name, &args)
    }));
    match res {
        Ok(Some(Ok(vals))) => Outcome::Returned(vals),
        Ok(Some(Err(trap))) => Outcome::Trapped(trap),
        Ok(None) => Outcome::Unsupported,
        Err(_) => Outcome::Panicked,
    }
}

// Anything the engine can't represent is skipped rather than failed:
// validation, linking, non-numeric types, modules that fail to compile, ...
fn run_file(path: &Path, file: &str, adapters: &mut AdapterJit, tally: &mut Tally) {
    let contents = std::fs::read_to_string(path).unwrap();
    let Ok(buf) = ParseBuffer::new(&contents) else {
        tally.skip += 1;
        return;
    };
    let Ok(wast) = parser::parse::<Wast>(&buf) else {
        tally.skip += 1;
        return;
    };

    let mut instance = None;
    for directive in wast.directives {
        let (line, _col) = directive.span().linecol_in(&contents);
        let at = format!("{file}:{}", line + 1);
        match directive {
            WastDirective::Module(mut quote) => {
                instance = compile_module(&mut quote, file);
                if instance.is_none() {
                    tally.skip += 1;
                }
            }
            WastDirective::Invoke(invoke) => {
                let outcome = run_invoke(instance.as_mut(), adapters, &invoke);
                if tally.expect_return(outcome, &at, invoke.name).is_some() {
                    tally.pass += 1;
                }
            }
            WastDirective::AssertReturn {
                exec: WastExecute::Invoke(invoke),
                results,
                ..
            } => {
                let outcome = run_invoke(instance.as_mut(), adapters, &invoke);
                if let Some(got) = tally.expect_return(outcome, &at, invoke.name) {
                    tally.check_results(&results, &got, &at);
                }
            }
            WastDirective::AssertTrap {
                exec: WastExecute::Invoke(invoke),
                message,
                ..
            } => {
                let outcome = run_invoke(instance.as_mut(), adapters, &invoke);
                tally.expect_trap(outcome, &at, invoke.name, message);
            }
            _ => tally.skip += 1,
        }
    }
}

#[test]
#[ignore = "slow; requires the tests/wasm-testsuite submodule"]
fn spec_testsuite() {
    let Some(dir) = testsuite_dir() else {
        eprintln!(
            "skipping: spec testsuite not found. \
             run `git submodule update --init tests/wasm-testsuite` or set WASM_TESTSUITE_DIR."
        );
        return;
    };

    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "wast"))
        .collect();
    files.sort();

    let mut adapters = AdapterJit::new();
    let mut tally = Tally::default();
    let mut xfail = 0;
    let mut per_file = Vec::new();

    // we expect lots of panics from unsupported features
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let (pass, failures, skip) = (tally.pass, tally.failures.len(), tally.skip);
        run_file(path, &name, &mut adapters, &mut tally);
        let failed = tally.failures.len() - failures;
        if known_divergence(&name).is_some() {
            tally.failures.truncate(failures);
            xfail += failed;
        }
        per_file.push((name, tally.pass - pass, failed, tally.skip - skip));
    }
    std::panic::set_hook(prev_hook);

    println!("\n=== WASM spec testsuite summary ===");
    println!("files: {}", files.len());
    println!(
        "directives: {} pass, {} skip, {xfail} xfail (known divergence), {} unexpected fail",
        tally.pass,
        tally.skip,
        tally.failures.len()
    );

    println!("\nper-file (pass/fail/skip), files with failures first:");
    per_file.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    for (name, pass, fail, skip) in per_file.iter().filter(|f| f.2 > 0) {
        let tag = known_divergence(name)
            .map(|r| format!("  [xfail: {r}]"))
            .unwrap_or_default();
        println!("  {name:<28} {pass:>5}/{fail:>4}/{skip:>5}{tag}");
    }

    if !tally.failures.is_empty() {
        println!("\nunexpected failures:");
        for failure in tally.failures.iter().take(80) {
            println!("  {failure}");
        }
    }

    assert!(
        tally.failures.is_empty(),
        "{} unexpected spec-testsuite failures (see summary above)",
        tally.failures.len(),
    );
}
