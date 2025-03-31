pub mod builtins;
pub mod concolic;
pub mod control;
pub mod feedback;
pub mod function;
pub mod instance;
pub mod instrumentation;
pub mod memory;
pub mod misc;
pub mod module;
pub mod numeric;
pub mod signals;
pub mod tracing;
pub mod util;
pub mod vmcontext;

use std::{
    any::Any,
    collections::BTreeSet,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use module::ModuleTranslator;
pub(crate) use util::wasm2ty;

pub(crate) use function::FuncTranslator;

use crate::{
    fuzzer::opts::StrategyOpts,
    instrumentation::{BBCoveragePass, Edge, EdgeCoveragePass, FunctionCoveragePass, Passes},
    ir::{Location, ModuleSpec},
};

use self::{
    feedback::FeedbackContext, instance::ModuleInstance, module::TrapKind, vmcontext::VMContext,
};

#[derive(Default, Debug)]
pub(crate) struct Stats {
    _start: Option<Instant>,
    pub reusable_stage_executions: usize,
    pub tracing_stage_executions: usize,
    pub traps: usize,
    pub traps_gone_wrong: usize,
    pub unstable_instrumentation_counter: usize,
    pub bus_rx: usize,
    pub bus_tx: usize,
    pub finds_own: usize,
    pub finds_imported: usize,
    pub wall_mutate_ns: u64,
    pub wall_reusable_ns: u64,
    pub wall_tracing_ns: u64,
    pub wall_initial_codegen_ns: u64,
    pub wall_rehydrate_ns: u64,
    pub exhaustive_execs: usize,
    pub exhaustive_finds: usize,
}

impl Stats {
    pub(crate) fn new() -> Self {
        Self {
            _start: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub(crate) fn format(&self, context: &Option<String>) -> String {
        let Self {
            _start,
            reusable_stage_executions,
            traps,
            traps_gone_wrong,
            unstable_instrumentation_counter,
            bus_rx,
            bus_tx,
            finds_own,
            finds_imported,
            wall_mutate_ns,
            wall_reusable_ns,
            wall_tracing_ns,
            wall_initial_codegen_ns,
            wall_rehydrate_ns,
            exhaustive_execs,
            exhaustive_finds,
            tracing_stage_executions,
        } = self;

        let elapsed = _start.as_ref().expect("stats from Stats::new").elapsed();
        let wall_accounted_ns = wall_mutate_ns
            + wall_reusable_ns
            + wall_tracing_ns
            + wall_initial_codegen_ns
            + wall_rehydrate_ns;

        let mut res = String::new();
        if let Some(context) = context.as_ref() {
            res += &format!("Stats for {context} {{\n");
        } else {
            res += "Stats {\n";
        }
        let execs = [
            ("reusable", reusable_stage_executions, wall_reusable_ns),
            ("tracing ", tracing_stage_executions, wall_tracing_ns),
        ];
        for (kind, &execs, &accounting_ns) in execs {
            if execs > 0 {
                let execs_per_second_total = execs as f64 / elapsed.as_secs_f64();
                let execs_per_second =
                    execs as f64 / Duration::from_nanos(accounting_ns).as_secs_f64();
                res += &format!("  {kind} stage execs: {execs:>9} ({execs_per_second_total:>9.2}/s wall, {execs_per_second:>10.2}/s perf)\n");
            }
        }
        let kv = [
            ("traps", traps),
            ("traps_gone_wrong", traps_gone_wrong),
            (
                "unstable_instrumentation_counter",
                unstable_instrumentation_counter,
            ),
            ("bus_rx", bus_rx),
            ("bus_tx", bus_tx),
            ("finds_own", finds_own),
            ("finds_imported", finds_imported),
            ("exhaustive_execs", exhaustive_execs),
            ("exhaustive_finds", exhaustive_finds),
        ];
        for (key, val) in kv {
            let val = *val;
            if val > 0 {
                res += &format!("  {key}: {val}\n");
            }
        }

        let timers = [
            ("mutate", wall_mutate_ns),
            ("reusable", wall_reusable_ns),
            ("tracing", wall_tracing_ns),
            ("initial_codegen", wall_initial_codegen_ns),
            ("rehydrate", wall_rehydrate_ns),
        ];
        for (key, val) in timers {
            if *val > 0 {
                let dur = Duration::from_nanos(*val);
                res += &format!("  {key}: {}\n", humantime::format_duration(dur));
            }
        }

        let unaccounted = elapsed - Duration::from_nanos(wall_accounted_ns);
        res += &format!(
            "  unaccounted: {}\n",
            humantime::format_duration(unaccounted)
        );

        res += "}";
        res
    }
}

#[derive(Clone, Hash, PartialEq, Eq, Default)]
pub(crate) struct SwarmConfig {
    pub discard_short_circuit_coverage: bool,

    pub avoid_functions: BTreeSet<u32>,
    pub avoid_bbs: BTreeSet<Location>,
    pub avoid_edges: BTreeSet<Edge>,
    pub must_include_functions: BTreeSet<u32>,
    pub must_include_bbs: BTreeSet<Location>,
    pub must_include_edges: BTreeSet<Edge>,

    pub input_size_limit: Option<u32>,
    pub instruction_limit: Option<u64>,
    pub memory_limit_pages: Option<u32>,
}
impl SwarmConfig {
    pub(crate) fn from_instruction_limit(instruction_limit: Option<u64>) -> Self {
        Self {
            instruction_limit,
            ..Default::default()
        }
    }

    pub(crate) fn input_alloc_size(&self) -> usize {
        // self.input_size_limit.unwrap_or(4096) as usize
        u16::MAX as usize
    }
}

impl std::fmt::Debug for SwarmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let SwarmConfig {
            discard_short_circuit_coverage,
            avoid_functions,
            avoid_bbs,
            avoid_edges,
            must_include_functions,
            must_include_bbs,
            must_include_edges,
            input_size_limit,
            instruction_limit,
            memory_limit_pages,
        } = self;
        let mut f = f.debug_struct("SwarmConfig");
        let mut skipped = false;
        fn field<V: std::fmt::Debug + Default + PartialEq>(
            f: &mut std::fmt::DebugStruct,
            name: &str,
            value: &V,
        ) -> bool {
            let is_default = value == &V::default();
            if !is_default {
                f.field(name, value);
            }
            is_default
        }
        skipped |= field(
            &mut f,
            "discard_short_circuit_coverage",
            discard_short_circuit_coverage,
        );
        skipped |= field(&mut f, "avoid_functions", avoid_functions);
        skipped |= field(&mut f, "avoid_bbs", avoid_bbs);
        skipped |= field(&mut f, "avoid_edges", avoid_edges);
        skipped |= field(&mut f, "must_include_functions", must_include_functions);
        skipped |= field(&mut f, "must_include_bbs", must_include_bbs);
        skipped |= field(&mut f, "must_include_edges", must_include_edges);
        skipped |= field(&mut f, "input_size_limit", input_size_limit);
        skipped |= field(&mut f, "instruction_limit", instruction_limit);
        skipped |= field(&mut f, "memory_limit_pages", memory_limit_pages);
        if skipped {
            f.finish_non_exhaustive()
        } else {
            f.finish()
        }
    }
}

pub(crate) trait PassesGen: fmt::Debug {
    fn generate_passes(&self) -> Passes;
}

#[derive(Debug, Clone)]
pub(crate) struct EmptyPassesGen;

impl PassesGen for EmptyPassesGen {
    fn generate_passes(&self) -> Passes {
        Passes::empty()
    }
}

pub(crate) struct SinglePassGen(
    std::cell::RefCell<Option<Box<dyn crate::instrumentation::ErasedInstrumentationPass>>>,
);
impl SinglePassGen {
    pub(crate) fn new(pass: Box<dyn crate::instrumentation::ErasedInstrumentationPass>) -> Self {
        Self(std::cell::RefCell::new(Some(pass)))
    }
}
impl PassesGen for SinglePassGen {
    fn generate_passes(&self) -> Passes {
        let mut res = Passes::empty();
        res.push(
            self.0
                .borrow_mut()
                .take()
                .expect("SinglePassGen used twice"),
        );
        res
    }
}

impl fmt::Debug for SinglePassGen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SinglePassGen")
            .field(&self.0.borrow().as_ref().map(|p| p.shortcode()))
            .finish()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FullFeedbackPasses {
    pub opts: FeedbackOptions,
    pub spec: Arc<ModuleSpec>,
}

impl PassesGen for FullFeedbackPasses {
    fn generate_passes(&self) -> Passes {
        use crate::instrumentation::*;

        let mut passes = Passes::empty();

        let FeedbackOptions {
            live_funcs,
            live_bbs,
            live_edges,
            cmpcov_hamming,
            cmpcov_absdist,
            perffuzz_func,
            perffuzz_bb,
            perffuzz_edge,
            perffuzz_edge_global,
            func_rec_depth,
            call_value_profile,
            func_input_size,
            func_input_size_cyclic,
            func_input_size_color,
            memory_op_value,
            memory_op_address,
            memory_store_prev_value,
            func_shortest_trace,
            edge_shortest_trace,
            func_longest_trace,
            path_hash_func,
            path_hash_edge,
        } = self.opts;

        macro_rules! add_pass {
            ($cond:expr, $pass:expr) => {
                if $cond {
                    passes.push_cc($pass);
                }
            };
        }

        let filter = |_loc: &Location| true;
        add_pass!(live_funcs, FunctionCoveragePass::new(&self.spec, filter));
        add_pass!(live_bbs, BBCoveragePass::new(&self.spec, filter));
        add_pass!(live_edges, EdgeCoveragePass::new(&self.spec, filter));

        macro_rules! add_pass {
            ($cond:expr, $pass:expr) => {
                if $cond {
                    passes.push_kv($pass);
                }
            };
        }

        add_pass!(
            cmpcov_hamming,
            CmpCoveragePass::new(CmpCovKind::Hamming, &self.spec, filter)
        );
        add_pass!(
            cmpcov_absdist,
            CmpCoveragePass::new(CmpCovKind::AbsDist, &self.spec, filter)
        );

        add_pass!(
            func_input_size,
            InputSizePass::new(InputComplexityMetric::Size, &self.spec, filter)
        );
        add_pass!(
            func_input_size_cyclic,
            InputSizePass::new(InputComplexityMetric::ByteDiversity, &self.spec, filter)
        );
        add_pass!(
            func_input_size_color,
            InputSizePass::new(InputComplexityMetric::DeBruijn, &self.spec, filter)
        );

        add_pass!(perffuzz_func, PerffuzzFunctionPass::new(&self.spec, filter));
        add_pass!(perffuzz_bb, PerffuzzBBPass::new(&self.spec, filter));
        add_pass!(
            perffuzz_edge,
            EdgeHitsInAFunctionPass::new(&self.spec, filter)
        );
        add_pass!(
            perffuzz_edge_global,
            PerffuzzEdgePass::new(&self.spec, filter)
        );
        add_pass!(
            func_rec_depth,
            FunctionRecursionDepthPass::new(&self.spec, filter)
        );

        add_pass!(
            memory_op_value,
            MemoryLoadValRangePass::new(&self.spec, filter)
        );
        add_pass!(
            memory_op_value,
            MemoryStoreValRangePass::new(&self.spec, filter)
        );
        add_pass!(
            memory_op_address,
            MemoryOpAddressRangePass::new(&self.spec, filter)
        );
        add_pass!(
            memory_store_prev_value,
            MemoryStorePrevValRangePass::new(&self.spec, filter)
        );

        add_pass!(
            call_value_profile,
            CallParamsRangePass::new(&self.spec, filter)
        );
        add_pass!(
            call_value_profile,
            CallParamsSetPass::new(&self.spec, filter)
        );
        add_pass!(
            call_value_profile,
            GlobalsRangePass::new(&self.spec, filter)
        );

        add_pass!(
            func_shortest_trace,
            FunctionShortestExecutionTracePass::new(&self.spec, filter)
        );
        add_pass!(
            edge_shortest_trace,
            EdgeShortestExecutionTracePass::new(&self.spec, filter)
        );
        add_pass!(
            func_longest_trace,
            FunctionLongestExecutionTracePass::new(&self.spec, filter)
        );

        macro_rules! add_pass {
            ($cond:expr, $pass:expr) => {
                if $cond {
                    passes.push_hash($pass);
                }
            };
        }

        add_pass!(path_hash_func, FuncPathHashPass::new(&self.spec, filter));
        add_pass!(path_hash_edge, EdgePathHashPass::new(&self.spec, filter));

        passes
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CompilationOptions {
    pub tracking: TrackingOptions,
    pub tracing: TracingOptions,
    pub swarm: SwarmConfig, // is `scope` a better name?
    pub verbose: bool,
    pub debug_trace: bool,
    pub kind: CompilationKind,
    pub optimize_for_compilation_time: bool,
}

impl CompilationOptions {
    pub fn new(
        tracking: &TrackingOptions,
        tracing: &TracingOptions,
        swarm: &SwarmConfig,
        kind: CompilationKind,
        debug_trace: bool,
        verbose: bool,
        optimize_for_compilation_time: bool,
    ) -> Self {
        Self {
            debug_trace: debug_trace
                || std::env::var("JITTRACE")
                    .map(|el| el == "1" || el == "thin" || el == "line")
                    .unwrap_or_default(),
            verbose: verbose
                || std::env::var("JITDEBUG")
                    .map(|el| el == "1")
                    .unwrap_or_default(),
            tracking: tracking.clone(),
            tracing: tracing.clone(),
            kind,
            swarm: swarm.clone(),
            optimize_for_compilation_time,
        }
    }

    #[rustfmt::skip]
    pub(crate) fn shortcode(&self, passes: &Passes) -> String {
        let mut s = String::new();
        s += match self.kind {
            CompilationKind::Reusable => "Reusable(",
            CompilationKind::Tracing => "Tracing(",
        };
        for p in passes.iter() {
            s += &format!("[{}]", p.shortcode());
        }
        if &s[s.len()-1..] == "(" { s += "<none>" }
        s += ", ";
        let &TracingOptions {
            cmplog: compare_log,
            stdout,
            concolic,
        } = &self.tracing;
        if compare_log { s += "[cmplog]" }
        if stdout { s += "[stdout]" }
        if concolic { s += "[concolic]" }
        if &s[s.len()-1..] == " " { s += "<none>" }
        s += ")";
        s
    }

    pub(crate) fn is_concolic(&self) -> bool {
        self.kind == CompilationKind::Tracing && self.tracing.concolic
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) enum CompilationKind {
    // Collect features into resettable feature maps / coverage dbs
    Reusable,
    // Trace inputs explicitly, collects cmplog
    // All (interesting) inputs are traced when they're included in the corpus
    Tracing,
}

#[derive(Clone, Hash, PartialEq, Eq, serde::Serialize)]
pub(crate) struct FeedbackOptions {
    pub live_funcs: bool,
    pub live_bbs: bool,
    pub live_edges: bool,
    pub cmpcov_hamming: bool,
    pub cmpcov_absdist: bool,
    pub perffuzz_func: bool,
    pub perffuzz_bb: bool,
    pub perffuzz_edge: bool,
    pub perffuzz_edge_global: bool,
    pub func_rec_depth: bool,
    // TODO: this also enables cmp value profile. rename or split?
    pub call_value_profile: bool,
    // TODO: add arithmetic value profiles? maybe just 8bit?
    pub func_input_size: bool,
    pub func_input_size_cyclic: bool,
    pub func_input_size_color: bool,
    pub memory_op_value: bool,
    pub memory_op_address: bool,
    pub memory_store_prev_value: bool,
    pub path_hash_func: bool,
    pub path_hash_edge: bool,
    pub func_shortest_trace: bool,
    pub edge_shortest_trace: bool,
    pub func_longest_trace: bool,
}

impl FeedbackOptions {
    pub(crate) fn minimal_code_coverage() -> Self {
        Self {
            live_funcs: true,
            live_bbs: true,
            live_edges: true,
            ..Self::nothing()
        }
    }

    pub(crate) fn nothing() -> Self {
        Self {
            live_funcs: false,
            live_bbs: false,
            live_edges: false,
            cmpcov_hamming: false,
            cmpcov_absdist: false,
            perffuzz_func: false,
            perffuzz_bb: false,
            perffuzz_edge: false,
            perffuzz_edge_global: false,
            func_rec_depth: false,
            call_value_profile: false,
            func_input_size: false,
            func_input_size_cyclic: false,
            func_input_size_color: false,
            memory_op_value: false,
            memory_op_address: false,
            memory_store_prev_value: false,
            path_hash_func: false,
            path_hash_edge: false,
            func_shortest_trace: false,
            edge_shortest_trace: false,
            func_longest_trace: false,
        }
    }

    pub(crate) fn all_instrumentation() -> Self {
        Self {
            live_funcs: true,
            live_bbs: true,
            live_edges: true,
            cmpcov_hamming: true,
            cmpcov_absdist: true,
            perffuzz_func: true,
            perffuzz_bb: true,
            perffuzz_edge: true,
            perffuzz_edge_global: true,
            func_rec_depth: true,
            call_value_profile: true,
            func_input_size: true,
            func_input_size_cyclic: true,
            func_input_size_color: true,
            memory_op_value: true,
            memory_op_address: true,
            memory_store_prev_value: true,
            func_shortest_trace: true,
            edge_shortest_trace: true,
            func_longest_trace: true,
            path_hash_func: true,
            path_hash_edge: true,
        }
    }
}

impl std::fmt::Debug for FeedbackOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("FeedbackOptions");
        let v = serde_json::to_value(self).unwrap();
        let mut skipped = false;
        for (k, v) in v.as_object().unwrap() {
            if v.as_bool().unwrap() {
                f.field(k, &true);
            } else {
                skipped = true;
            }
        }
        if skipped {
            f.finish_non_exhaustive()
        } else {
            f.finish()
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub(crate) struct TracingOptions {
    pub cmplog: bool,
    pub stdout: bool,
    pub concolic: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub(crate) struct TrackingOptions {
    fuel: bool,
    // TODO: different kinds of taint?
    // - def-use
    //   * as a general signal
    //   * minimize distance to left/right bounds?
    // - input / non-input
    // - "complexity": #ops to source
    // - specific input byte contributions?
}

pub(crate) struct JitStage {
    kind: CompilationKind,
    pub(crate) instance: Option<ModuleInstance>,
    pub(crate) inp_ptr: Option<i32>,
    fuzz_func: Option<*const u8>,
    run_from_snapshot: bool,
}

impl JitStage {
    fn new_lazy(kind: CompilationKind, run_from_snapshot: bool) -> Self {
        Self {
            kind,
            instance: None,
            inp_ptr: None,
            fuzz_func: None,
            run_from_snapshot,
        }
    }

    fn ensure_init(&mut self, spec: &ModuleSpec, opts: &CompilationOptions, passes: &mut Passes) {
        assert_eq!(opts.kind, self.kind);
        if self.instance.is_none() {
            let action = if self.kind != CompilationKind::Reusable {
                format!("Generating code for kind {:?}", self.kind)
            } else if passes.iter().len() > 0 {
                format!("Generating code with {} passes", passes.iter().len())
            } else {
                "Generating code".into()
            };
            println!("{action} ...");
            let modtrans = ModuleTranslator::new(spec, opts);
            let instance = modtrans.compile_to_instance(passes);
            println!(
                "{action} ... done (size: {})",
                humansize::format_size(instance.code_size, humansize::DECIMAL)
            );

            let fuzz_fn = unsafe {
                std::mem::transmute::<*const u8, fn(i32, i32, *const VMContext) -> i32>(
                    instance.get_export("LLVMFuzzerTestOneInput"),
                )
            };
            self.fuzz_func = Some(fuzz_fn as *const u8);
            assert!(self.instance.is_none());
            self.instance = Some(instance);
            self.inp_ptr = None;
        }

        if !self.run_from_snapshot {
            let instance = self.instance.as_mut().unwrap();
            if instance.vmctx.tainted {
                instance.vmctx.reset(spec);
            }
        }

        if self.inp_ptr.is_none() {
            let instance = self.instance.as_mut().unwrap();
            // println!("reset vmctx because inp_ptr is_none {:?}", self.kind);
            instance.vmctx.reset(spec);

            // for initializer and malloc call: set reasonable limits
            instance.vmctx.fuel_init = 100_000_000;
            instance.vmctx.heap_pages_limit_soft = u32::MAX;
            instance.vmctx.heap_pages_limit_hard = 1024 * 16;

            let initializer_symbol = match (
                spec.start_func,
                spec.exported_funcs.contains_key("_initialize"),
                spec.exported_funcs.contains_key("init"),
            ) {
                (None, false, false) => None,
                (Some(_start_func), _, _) => {
                    unimplemented!("we expect `clang -mexec-model=reactor` artifacts.")
                }
                (None, true, false) => Some("_initialize"),
                (None, false, true) => Some("init"),
                (_, _, _) => panic!("unexpected initializer symbols found"),
            };
            if let Some(initializer_symbol) = initializer_symbol {
                // TODO: check type?
                let initializer_fn = unsafe {
                    std::mem::transmute::<*const u8, fn(*const VMContext)>(
                        instance.get_export(initializer_symbol),
                    )
                };
                instance
                    .enter(move |vmctx| initializer_fn(vmctx))
                    .expect("initializer shouldn't trap");
            }

            if spec.exported_funcs.contains_key("LLVMFuzzerInitialize") {
                let fuzzer_init_fn = unsafe {
                    std::mem::transmute::<
                        *const u8,
                        fn(*mut usize, *mut *const *const u8, *const VMContext),
                    >(instance.get_export("LLVMFuzzerInitialize"))
                };
                instance
                    .enter(move |vmctx| {
                        fuzzer_init_fn(std::ptr::null_mut(), std::ptr::null_mut(), vmctx)
                    })
                    .expect("LLVMFuzzerInitialize shouldn't trap");
            }

            let malloc_symbol = crate::ir::wasmfuzz_abi::malloc_symbol(spec);
            let malloc_fn = unsafe {
                std::mem::transmute::<*const u8, fn(u32, *const VMContext) -> i32>(
                    instance.get_export(malloc_symbol),
                )
            };
            assert_eq!(instance.vmctx.input_size, 0);
            let input_alloc_size = opts.swarm.input_alloc_size() as u32;
            let inp_ptr = instance
                .enter(move |vmctx| malloc_fn(input_alloc_size, vmctx))
                .expect("malloc shouldn't trap");
            self.inp_ptr = Some(inp_ptr);
            instance.vmctx.fuel_init = opts.swarm.instruction_limit.unwrap_or(u32::MAX as u64);
            instance.vmctx.heap_pages_limit_soft =
                opts.swarm.memory_limit_pages.unwrap_or(u32::MAX);
            instance.vmctx.heap_pages_limit_hard = crate::MEMORY_PAGES_LIMIT;
            if self.run_from_snapshot {
                instance.vmctx.snapshot();
            }
        }
    }

    fn reset(&mut self, spec: &ModuleSpec) {
        if self.run_from_snapshot {
            return;
        }
        // NOTE: this'll be incorrect for wasms with initializers.
        // make sure we're always preinitialized?
        if let Some(instance) = self.instance.as_mut() {
            instance.vmctx.feedback.reset();
            instance.vmctx.reset(spec);
        }
        self.inp_ptr = None;
    }

    fn run(&mut self, inp: &[u8]) -> Result<(), TrapKind> {
        let instance = self.instance.as_mut().unwrap();
        let fuzz_func = self.fuzz_func.unwrap();
        let inp_ptr = self.inp_ptr.unwrap();

        if self.run_from_snapshot {
            instance.vmctx.restore();
        }

        let f =
            unsafe { std::mem::transmute::<*const u8, fn(i32, i32, *mut VMContext)>(fuzz_func) };
        let inp_len = inp.len() as i32;
        instance.write_input(inp_ptr as _, inp);
        let res = instance.enter(|vmctx| f(inp_ptr, inp_len, vmctx));
        match res {
            Err(TrapKind::SwarmShortCircuit(_)) => {
                // TODO: this logic seems sus
                // eprintln!("{:?}", res);
                Ok(())
            }
            _ => res,
        }
    }

    pub(crate) fn feedback(&self) -> &FeedbackContext {
        assert!(self.kind == CompilationKind::Reusable || self.kind == CompilationKind::Tracing);
        &self.instance.as_ref().unwrap().vmctx.feedback
    }

    fn reset_feedback(&mut self) {
        self.instance.as_mut().unwrap().vmctx.feedback.reset()
    }
}

pub(crate) struct JitFuzzingSessionBuilder {
    mod_spec: Arc<ModuleSpec>,
    tracing: TracingOptions,
    debug_trace: bool,
    verbose: bool,
    swarm: SwarmConfig,
    passes_generator: Arc<dyn PassesGen>,
    run_from_snapshot: bool,
    optimize_for_compilation_time: bool,
}

impl JitFuzzingSessionBuilder {
    pub fn new(mod_spec: Arc<ModuleSpec>) -> Self {
        let sopts = StrategyOpts::default();
        let swarm = SwarmConfig {
            instruction_limit: sopts.instruction_limit,
            input_size_limit: Some(4096),
            memory_limit_pages: None,
            ..Default::default()
        };
        Self {
            tracing: TracingOptions::default(),
            debug_trace: false,
            verbose: false,
            swarm,
            passes_generator: Arc::new(FullFeedbackPasses {
                opts: FeedbackOptions::minimal_code_coverage(),
                spec: mod_spec.clone(),
            }),
            run_from_snapshot: *sopts.run_from_snapshot,
            optimize_for_compilation_time: false,
            mod_spec,
        }
    }

    pub fn build(self) -> JitFuzzingSession {
        JitFuzzingSession::from_builder(self)
    }

    pub(crate) fn feedback(mut self, feedback: FeedbackOptions) -> Self {
        self.passes_generator = Arc::new(FullFeedbackPasses {
            opts: feedback,
            spec: self.mod_spec.clone(),
        });
        self
    }

    pub(crate) fn tracing(mut self, tracing: TracingOptions) -> Self {
        self.tracing = tracing;
        self
    }

    pub(crate) fn debug(mut self, debug_trace: bool, verbose: bool) -> Self {
        self.debug_trace = debug_trace;
        self.verbose = verbose;
        self
    }

    pub(crate) fn input_size_limit(mut self, input_size_limit: u32) -> Self {
        self.swarm.input_size_limit = Some(input_size_limit);
        self
    }

    pub(crate) fn run_from_snapshot(mut self, run_from_snapshot: bool) -> Self {
        self.run_from_snapshot = run_from_snapshot;
        self
    }

    pub(crate) fn instruction_limit(mut self, instruction_limit: Option<u64>) -> Self {
        self.swarm.instruction_limit = instruction_limit;
        self
    }

    pub(crate) fn swarm(mut self, swarm: SwarmConfig) -> Self {
        self.swarm = swarm;
        self
    }

    pub(crate) fn passes_generator(mut self, passes_generator: Arc<dyn PassesGen>) -> Self {
        self.passes_generator = passes_generator;
        self
    }

    pub(crate) fn optimize_for_compilation_time(mut self, val: bool) -> Self {
        self.optimize_for_compilation_time = val;
        self
    }
}

// TODO: move to vm.rs?
pub(crate) struct JitFuzzingSession {
    pub(crate) spec: Arc<ModuleSpec>,
    tracking: TrackingOptions,
    tracing: TracingOptions,
    pub(crate) reusable_stage: JitStage,
    pub(crate) tracing_stage: JitStage,
    reusable_exec_history: Vec<Vec<u8>>,
    run_from_snapshot: bool,
    debug_trace: bool,
    verbose: bool,
    optimize_for_compilation_time: bool,
    pub(crate) swarm: SwarmConfig,
    pub(crate) passes: Passes,
}

impl JitFuzzingSession {
    pub(crate) fn builder(mod_spec: Arc<ModuleSpec>) -> JitFuzzingSessionBuilder {
        JitFuzzingSessionBuilder::new(mod_spec)
    }

    fn from_builder(builder: JitFuzzingSessionBuilder) -> Self {
        let JitFuzzingSessionBuilder {
            mod_spec,
            tracing,
            debug_trace,
            verbose,
            swarm,
            passes_generator,
            run_from_snapshot,
            optimize_for_compilation_time,
        } = builder;

        let tracking = TrackingOptions {
            fuel: swarm.instruction_limit.is_some(),
        };
        Self {
            spec: mod_spec,
            tracking,
            tracing,
            reusable_stage: JitStage::new_lazy(CompilationKind::Reusable, run_from_snapshot),
            tracing_stage: JitStage::new_lazy(CompilationKind::Tracing, run_from_snapshot),
            reusable_exec_history: Vec::new(),
            run_from_snapshot,
            debug_trace,
            verbose,
            swarm,
            optimize_for_compilation_time,
            passes: passes_generator.generate_passes(),
        }
    }

    pub(crate) fn initialize(&mut self, stats: &mut Stats) {
        // assert!(self.reusable_stage.inp_ptr.is_none());
        self.reusable_stage.inp_ptr.take();
        if let Some(inst) = self.reusable_stage.instance.as_mut() {
            inst.vmctx.reset_to_initial(&self.spec);
        }

        let start = Instant::now();
        self.reusable_stage.ensure_init(
            &self.spec,
            &CompilationOptions::new(
                &self.tracking,
                &self.tracing,
                &self.swarm,
                self.reusable_stage.kind,
                self.debug_trace,
                self.verbose,
                self.optimize_for_compilation_time,
            ),
            &mut self.passes,
        );
        stats.wall_initial_codegen_ns += start.elapsed().as_nanos() as u64;
        assert!(self.reusable_stage.inp_ptr.is_some());
        // save malloc coverage
        let new_cov = !self.scan_passes_for_coverage().is_empty();
        let have_codecov_pass = self.passes.iter().any(|pass| {
            let pass = pass as &dyn std::any::Any;
            pass.is::<FunctionCoveragePass>()
                || pass.is::<BBCoveragePass>()
                || pass.is::<EdgeCoveragePass>()
        });
        assert!(
            new_cov || !have_codecov_pass,
            "we should uncover some code in malloc"
        );
    }

    // TODO(refactor)
    pub(crate) fn tracing_context(&self) -> &FeedbackContext {
        self.tracing_stage.feedback()
    }

    pub(crate) fn run_reusable(
        &mut self,
        inp: &[u8],
        fuzzing: bool,
        stats: &mut Stats,
    ) -> RunResult {
        let start = Instant::now();
        stats.reusable_stage_executions += 1;
        if !self.run_from_snapshot {
            if inp.len() <= 1024 && self.reusable_exec_history.len() <= 1024 {
                self.reusable_exec_history.push(inp.to_vec());
            } else {
                self.reusable_exec_history.push(Vec::new());
            }
        }
        self.reusable_stage.ensure_init(
            &self.spec,
            &CompilationOptions::new(
                &self.tracking,
                &self.tracing,
                &self.swarm,
                self.reusable_stage.kind,
                self.debug_trace,
                self.verbose,
                self.optimize_for_compilation_time,
            ),
            &mut self.passes,
        );
        self.reusable_stage.reset_feedback();

        let trap_kind = self.reusable_stage.run(inp).err();
        stats.wall_reusable_ns += start.elapsed().as_nanos() as u64;
        let novel_coverage_passes = self.scan_passes_for_coverage();

        // optionally discard coverage if short circuit trap
        if let Some(trap_kind) = &trap_kind {
            if trap_kind.is_short_circuit() && self.swarm.discard_short_circuit_coverage {
                return RunResult {
                    trap_kind: Some(trap_kind.clone()),
                    novel_coverage: false,
                    novel_coverage_passes: Vec::new(),
                };
            }
        }

        let res = RunResult {
            novel_coverage: !novel_coverage_passes.is_empty(),
            trap_kind,
            novel_coverage_passes,
        };

        if !fuzzing && res.is_crash() {
            println!("[!!] vanilla reusable stage died with {}, saving execution history before going down...", res.trap_kind.as_ref().unwrap().display(&self.spec));
            let _ = std::fs::create_dir("/tmp/wasmfuzz-flight-recorder/");
            let _ = std::fs::write("/tmp/wasmfuzz-flight-recorder/last.bin", inp);
            for (i, el) in self.reusable_exec_history.iter().enumerate() {
                let _ = std::fs::write(
                    format!("/tmp/wasmfuzz-flight-recorder/input_{i:06}.bin"),
                    el,
                );
            }
        }
        res
    }

    pub(crate) fn run(&mut self, inp: &[u8], stats: &mut Stats) -> RunResult {
        if !self.run_from_snapshot && self.reusable_exec_history.len() > 100_000 {
            // periodically reset state and execution history when running without snapshots
            self.run_reusable_fresh(inp, true, stats)
        } else {
            self.run_reusable(inp, true, stats)
        }
    }

    pub(crate) fn run_reusable_fresh(
        &mut self,
        input: &[u8],
        fuzzing: bool,
        stats: &mut Stats,
    ) -> RunResult {
        if !self.run_from_snapshot {
            self.reusable_stage.reset(&self.spec);
            self.reusable_exec_history.clear();
        }
        self.run_reusable(input, fuzzing, stats)
    }

    pub(crate) fn run_tracing_fresh(
        &mut self,
        input: &[u8],
        stats: &mut Stats,
    ) -> Result<&FeedbackContext, TrapKind> {
        if !self.run_from_snapshot {
            self.tracing_stage.reset(&self.spec);
        }
        self.tracing_stage.ensure_init(
            &self.spec,
            &CompilationOptions::new(
                &self.tracking,
                &self.tracing,
                &self.swarm,
                self.tracing_stage.kind,
                self.debug_trace,
                self.verbose,
                self.optimize_for_compilation_time,
            ),
            &mut self.passes,
        );
        let start = Instant::now();
        stats.tracing_stage_executions += 1;
        self.tracing_stage.reset_feedback();
        self.tracing_stage.run(input)?;
        stats.wall_tracing_ns += start.elapsed().as_nanos() as u64;
        Ok(self.tracing_context())
    }

    fn scan_passes_for_coverage(&mut self) -> Vec<&'static str> {
        tracy_full::zone!("JitFuzzingSession::scan_passes_for_coverage");
        let mut res = Vec::new();
        for pass in self.passes.iter_mut() {
            if pass.update_and_scan_coverage() {
                res.push(pass.shortcode());
            }
        }
        res
    }

    pub(crate) fn reset_pass_coverage(&mut self) {
        tracy_full::zone!("JitFuzzingSession::reset_pass_coverage");
        for pass in self.passes.iter_mut() {
            pass.reset_coverage();
        }
    }

    pub(crate) fn reset_pass_coverage_keep_saved(&mut self) {
        tracy_full::zone!("JitFuzzingSession::reset_pass_coverage_keep_saved");
        for pass in self.passes.iter_mut() {
            pass.reset_coverage_keep_saved();
        }
    }

    pub(crate) fn get_pass<T: 'static>(&self) -> &T {
        for pass in self.passes.iter() {
            if let Some(pass) = (pass as &dyn Any).downcast_ref::<T>() {
                return pass;
            }
        }
        panic!("pass not found");
    }

    pub(crate) fn get_passes<T: 'static>(&self) -> Vec<&T> {
        let mut passes = Vec::new();
        for pass in self.passes.iter() {
            if let Some(pass) = (pass as &dyn Any).downcast_ref::<T>() {
                passes.push(pass);
            }
        }
        passes
    }

    pub(crate) fn get_edge_cov(&self) -> Option<usize> {
        self.get_passes::<EdgeCoveragePass>()
            .iter()
            .map(|p| p.coverage.iter_covered_keys().count())
            .max()
    }
}

#[derive(Debug)]
pub(crate) struct RunResult {
    pub novel_coverage: bool,
    pub trap_kind: Option<TrapKind>,
    pub novel_coverage_passes: Vec<&'static str>,
}

impl RunResult {
    pub(crate) fn expect_ok(&self) {
        // assert!(self.trap_kind.is_none());
        if self.is_crash() {
            let trap_kind = self.trap_kind.as_ref().unwrap();
            panic!("execution trapped with {:?} which indicates a crash. crashing runs are not expected in this context", trap_kind);
        }
    }

    pub(crate) fn is_crash(&self) -> bool {
        self.trap_kind.as_ref().is_some_and(|x| {
            debug_assert!(x.is_coverage_trap() || x.is_short_circuit() || x.is_crash());
            x.is_crash()
        })
    }

    pub(crate) fn print_cov_update(&self, sess: &JitFuzzingSession, corpus_count: usize) {
        let new_fts = self.novel_coverage_passes.join(", ");
        let edges = sess
            .get_passes::<EdgeCoveragePass>()
            .iter()
            .map(|p| p.coverage.iter_covered_keys().count())
            .max()
            .unwrap_or(0);
        let funcs = sess
            .get_passes::<FunctionCoveragePass>()
            .iter()
            .map(|p| p.coverage.iter_covered_keys().count())
            .max()
            .unwrap_or(0);
        println!(
            "[funcs: {:>3} edges: {:>5} corp: {:>4}] new features: {}",
            funcs, edges, corpus_count, new_fts
        );
    }
}
