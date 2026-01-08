use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock, mpsc},
    time::Instant,
};

use clap::Parser;
use humantime::Duration;
use rand::{Rng, SeedableRng, prelude::*, rngs::StdRng};

use crate::{
    HashSet,
    instrumentation::{
        BBCoveragePass, Edge, EdgeCoveragePass, EdgeShortestExecutionTracePass, FeedbackLattice,
        FuncIdx, FunctionCoveragePass, Passes,
    },
    ir::{Location, ModuleSpec},
    jit::{
        FeedbackOptions, JitFuzzingSession, JitFuzzingSessionBuilder, PassesGen, RunResult, Stats,
        SwarmConfig,
    },
};

#[derive(Debug, Parser, Clone)]
pub(crate) struct CliOpts {
    #[clap(flatten)]
    pub g: super::opts::GeneralOpts,
    #[clap(long, default_value = "3m")]
    pub config_interval: Duration,
    #[clap(long)]
    pub timeout: Option<Duration>,
    #[clap(long)]
    pub cores: Option<usize>,
    // Delay thread startup in multi-core setting.
    // Can help with peak memory usage and tames the thundering herd.
    #[clap(long, default_value = "100ms")]
    pub stagger_cores: Duration,

    #[cfg(feature = "reports")]
    #[clap(long)]
    pub live_html_coverage: Option<PathBuf>,

    #[clap(long, env)]
    pub experiment: Option<Experiment>,

    #[clap(long, default_value = "30m")]
    pub expire_corpus_after: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Experiment {
    UseBusInputs,
    SwarmFocusEdge,
    Snapshot,
    OnlyEdgeCoverage,
    PassAblation,
}
impl std::str::FromStr for Experiment {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "use-bus-inputs" => Self::UseBusInputs,
            "snapshot" => Self::Snapshot,
            "swarm-focus-edge" => Self::SwarmFocusEdge,
            "only-edge-coverage" => Self::OnlyEdgeCoverage,
            "pass-ablation" => Self::PassAblation,
            _ => return Err("unknown Experiment".to_owned()),
        })
    }
}

#[derive(Clone)]
pub(crate) struct OrchestratorHandle {
    // pub Arc<Mutex<Orchestrator>>
    chan: mpsc::Sender<(OrcMessage, mpsc::SyncSender<OrcMessage>)>,
    corpus: Arc<RwLock<SharedCorpus>>,
}

enum OrcMessage {
    ReqSuggest,
    ReqReportFinds(Vec<Vec<u8>>),
    ReqShouldContinue,
    ReqShutdown,
    ReqLoadCorpus(Vec<Vec<u8>>),

    RespOk,
    RespSuggest(Box<Config>),
    RespShouldContinue(bool),
    RespInvalid,
}

impl OrchestratorHandle {
    pub fn new(module: Arc<ModuleSpec>, opts: CliOpts) -> Self {
        let (tx, rx) = mpsc::channel::<(OrcMessage, mpsc::SyncSender<OrcMessage>)>();
        let corpus = SharedCorpus::new(&opts);
        let corpus_ = corpus.clone();

        let _thread_handle = std::thread::Builder::new()
            .stack_size(32 << 20) // TODO: look into why generated code doesn't probe the stack any more?
            .name("orchestrator".to_owned())
            .spawn(move || {
                let mut orc = Orchestrator::new(module, opts, corpus_);
                while let Ok((req, tx)) = rx.recv() {
                    let resp = match req {
                        OrcMessage::ReqSuggest => OrcMessage::RespSuggest(orc.suggest().into()),
                        OrcMessage::ReqShouldContinue => {
                            OrcMessage::RespShouldContinue(orc.should_continue())
                        }
                        OrcMessage::ReqReportFinds(finds) => {
                            let mut update_live_coverage = false;
                            for input in finds {
                                let res = orc.report_find(&input);
                                update_live_coverage |=
                                    res.map(|x| x.novel_coverage).unwrap_or(false);
                            }
                            let mut corpus = orc.corpus.write().unwrap();
                            corpus.cull_and_update_weights();
                            drop(corpus);
                            if update_live_coverage {
                                orc.update_live_coverage();
                                orc.frontier_bbs = orc.compute_frontier().into_iter().collect();
                            }
                            OrcMessage::RespOk
                        }
                        OrcMessage::ReqShutdown => {
                            tx.send(OrcMessage::RespOk).unwrap();
                            break;
                        }
                        OrcMessage::ReqLoadCorpus(corpus) => {
                            let _ = orc.load_corpus(&corpus);
                            orc.update_live_coverage();
                            OrcMessage::RespOk
                        }
                        _ => OrcMessage::RespInvalid,
                    };
                    tx.send(resp).unwrap();
                }
            });

        Self { chan: tx, corpus }
    }

    fn req(&self, req: OrcMessage) -> OrcMessage {
        let (tx, rx) = mpsc::sync_channel(1);
        self.chan.send((req, tx)).unwrap();
        rx.recv().unwrap()
    }

    pub fn suggest(&self) -> Config {
        let resp = self.req(OrcMessage::ReqSuggest);
        match resp {
            OrcMessage::RespSuggest(config) => *config,
            _ => unreachable!(),
        }
    }

    pub fn should_continue(&self) -> bool {
        let resp = self.req(OrcMessage::ReqShouldContinue);
        match resp {
            OrcMessage::RespShouldContinue(v) => v,
            _ => unreachable!(),
        }
    }

    pub fn shutdown(&self) {
        self.req(OrcMessage::ReqShutdown);
    }

    pub fn report_finds(&self, inputs: Vec<Vec<u8>>) {
        let resp = self.req(OrcMessage::ReqReportFinds(inputs));
        assert!(matches!(resp, OrcMessage::RespOk));
    }

    pub fn fetch_corpus(&self) -> Vec<Arc<[u8]>> {
        self.corpus.read().unwrap().sample(&mut rand::rng())
    }

    pub fn load_corpus(&self, seed_corpus: Vec<Vec<u8>>) {
        let resp = self.req(OrcMessage::ReqLoadCorpus(seed_corpus));
        assert!(matches!(resp, OrcMessage::RespOk));
    }
}

struct Entry {
    input: Arc<[u8]>,
    weight: f32,
    last_seen_used: Instant,
}

pub(crate) struct SharedCorpus {
    disk_path: Option<PathBuf>,
    entries: crate::HashMap<Box<[u8]>, Entry>,
    // entries: Vec<Entry>,
    // seen: HashSet<Box<[u8]>>,
    // last_seen: crate::HashMap<Box<[u8]>, Instant>,
    soft_cull_threshold: std::time::Duration,
    hard_cull_threshold: std::time::Duration,
}

impl SharedCorpus {
    fn new(opts: &CliOpts) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            disk_path: opts.g.out_dir(),
            entries: crate::HashMap::default(),
            soft_cull_threshold: *opts.config_interval,
            hard_cull_threshold: *opts.expire_corpus_after,
        }))
    }
    // TODO: re-scan directory periodically?

    fn cull_and_update_weights(&mut self) {
        let Some(max) = self.entries.values().map(|e| e.last_seen_used).max() else {
            return;
        };

        if let Some(disk_path) = self.disk_path.as_ref() {
            for e in self.entries.values() {
                if max.duration_since(e.last_seen_used) >= self.hard_cull_threshold {
                    let p = Self::get_inp_path(disk_path, &e.input);
                    eprintln!(
                        "removing {:?}: last used {:?} ago",
                        p,
                        humantime::Duration::from(e.last_seen_used.elapsed())
                    );
                    let _ = std::fs::remove_file(p);
                }
            }
        }

        self.entries
            .retain(|_, e| max.duration_since(e.last_seen_used) < self.hard_cull_threshold);

        for e in self.entries.values_mut() {
            if max.duration_since(e.last_seen_used) < self.soft_cull_threshold {
                e.weight = 1.0;
            } else {
                let t = max.duration_since(e.last_seen_used) - self.soft_cull_threshold;
                let t = t.as_secs_f64()
                    / (self.hard_cull_threshold - self.soft_cull_threshold).as_secs_f64();
                e.weight = 1.0 - (t as f32);
            }
        }
    }

    fn insert(&mut self, input: &[u8], now: Instant) -> bool {
        if let Some(e) = self.entries.get_mut(input) {
            e.last_seen_used = now;
            false
        } else {
            self.entries.insert(
                input.to_vec().into_boxed_slice(),
                Entry {
                    input: input.to_vec().into_boxed_slice().into(),
                    last_seen_used: now,
                    weight: 1.0,
                },
            );

            if let Some(disk_path) = self.disk_path.as_ref() {
                let p = Self::get_inp_path(disk_path, input);
                if !p.is_file() {
                    let _ = std::fs::create_dir_all(disk_path);
                    let _ = std::fs::write(&p, input);
                    println!("saved {p:?}");
                }
            }
            true
        }
    }

    fn sample<R: RngCore>(&self, rng: &mut R) -> Vec<Arc<[u8]>> {
        let mut res = Vec::new();
        for e in self.entries.values() {
            if e.weight >= rng.random() {
                res.push(e.input.clone());
            }
        }
        res.shuffle(rng);
        // dbg!(res.len(), self.entries.len());
        res
    }

    fn get_inp_path(base_path: &Path, input: &[u8]) -> PathBuf {
        let mut inp_path = base_path.to_path_buf();
        let inphash = md5::compute(input);
        inp_path.push(format!("{inphash:x}"));
        inp_path
    }
}

// `Orchestrator` suggests fuzzer configurations over time.
// TODO: implement some kind of bandit for config options?
// TODO: suggest timelines?
// TODO: keep track of
//       * covered funcs/edges
//       * covered funcs/edges that are not covered in every input <- others aren't useful scopes
//       * time-to-reach-edge
// TODO: use this to suggest _scopes_ with time and memory limits
// TODO: maintain a set of _interesting_ edges? => ones that seem to affect control flow
pub(crate) struct Orchestrator {
    start: Instant,
    last_func_find: Instant,
    codecov_sess: JitFuzzingSession,
    // func_reachcounts: crate::HashMap<FuncIdx, u32>,
    // edge_reachcounts: crate::HashMap<Edge, u32>,
    // func_min_fuel: crate::HashMap<FuncIdx, u64>,
    // func_min_memory: crate::HashMap<FuncIdx, u64>,
    module: Arc<ModuleSpec>,
    rng: StdRng,
    found_crashes: bool,
    opts: CliOpts,
    corpus: Arc<RwLock<SharedCorpus>>,
    init_funcs: HashSet<FuncIdx>,
    init_edges: HashSet<Edge>,
    config_epoch: usize,
    frontier_bbs: Vec<Location>,
}

impl Orchestrator {
    fn new(module: Arc<ModuleSpec>, opts: CliOpts, corpus: Arc<RwLock<SharedCorpus>>) -> Self {
        let now = Instant::now();
        let mut codecov_sess = JitFuzzingSessionBuilder::new(module.clone())
            .feedback(FeedbackOptions {
                live_funcs: true,
                live_bbs: true,
                live_edges: true,
                edge_shortest_trace: true,
                ..FeedbackOptions::nothing()
            })
            .instruction_limit(Some(750_000_000))
            .input_size_limit(u16::MAX as u32)
            .build();
        codecov_sess.run(b"DUMMY", &mut Stats::default());
        let edges_pass = codecov_sess.get_pass::<EdgeCoveragePass>();
        let funcs_pass = codecov_sess.get_pass::<FunctionCoveragePass>();
        let init_edges = edges_pass.coverage.iter_covered_keys().collect();
        let init_funcs = funcs_pass.coverage.iter_covered_keys().collect();
        Self {
            start: now,
            last_func_find: now,
            opts,
            codecov_sess,
            // func_reachcounts: Default::default(),
            // edge_reachcounts: Default::default(),
            module,
            rng: StdRng::from_os_rng(),
            found_crashes: false,
            corpus,
            init_funcs,
            init_edges,
            config_epoch: 0,
            frontier_bbs: Vec::new(),
        }
    }

    pub fn load_corpus(&mut self, inputs: &[Vec<u8>]) -> Result<(), ()> {
        for (i, input) in inputs.iter().enumerate() {
            if i > 16 && (i + 1).is_power_of_two() {
                let edges = self.codecov_sess.get_edge_cov().unwrap_or(0);
                eprintln!(
                    "loading corpus: {}/{} entries [edges: {edges:>5}] ...",
                    i + 1,
                    inputs.len()
                );
            }
            // saves all inputs
            let res = self.add_corpus(input);
            if let Some(res) = res
                && res.is_crash()
            {
                eprintln!("load_corpus with crashing input! {res:?}");
                return Err(());
            }
        }
        if !inputs.is_empty() {
            let edges = self.codecov_sess.get_edge_cov().unwrap_or(0);
            eprintln!(
                "done loading: {} entries [edges: {edges:>5}] ...",
                inputs.len(),
            );
        }
        Ok(())
    }

    pub fn report_find(&mut self, /*config: &Config,*/ input: &[u8]) -> Option<RunResult> {
        // TODO: apply some kind of bandit on config?
        let res = self.add_corpus(input);

        if let Some(path) = self.opts.g.out_dir() {
            let mut inp_path = path.clone();
            let inphash = md5::compute(input);
            inp_path.push(format!("{inphash:x}"));
            if !inp_path.is_file() {
                let _ = std::fs::create_dir_all(path);
                let _ = std::fs::write(&inp_path, input);
                println!("saved {inp_path:?}");
            }
        }

        res
    }

    pub fn suggest(&mut self) -> Config {
        let mut timeout = *self.opts.config_interval;
        if let Some(tm) = self.opts.timeout.as_deref() {
            let tm_remaining = (*tm).saturating_sub(self.start.elapsed());
            timeout = timeout.min(tm_remaining);
        }

        self.config_epoch += 1;
        if self.config_epoch < 4 {
            let instruction_limit =
                (self.config_epoch != 3).then_some(1_000_000 * self.config_epoch as u64);
            let instruction_limit = Some(instruction_limit.unwrap_or(750_000_000)); // TODO
            let mut swarm = SwarmConfig::from_instruction_limit(instruction_limit);
            swarm.input_size_limit = Some(1024 * self.config_epoch as u32);
            // First config: no additional feedback guidance.
            let mut opts = FeedbackOptions::minimal_code_coverage();
            opts.cmpcov_hamming = true;
            if self.config_epoch > 0 {
                opts.edge_shortest_trace = true;
            }
            return Config {
                passes: OrcPassesGen {
                    opts,
                    spec: self.module.clone(),
                    swarm: swarm.clone(),
                    instr_only_funcs: None,
                },
                swarm,
                timeout,
            };
        }

        let is_saturated = self.coverage_is_saturated();
        // let apply_memlimit = self.rng.random_ratio(9, 10);
        let apply_fuellimit = self.rng.random_ratio(9, 10);

        // let target_function = None;
        let mut target_edge = None;
        let mut target_bb = None;

        if is_saturated && self.rng.random_ratio(5, 10) {
            // filter instrumentation sites?
        }

        if is_saturated {
            if self.rng.random() && !self.frontier_bbs.is_empty() {
                target_bb =
                    Some(self.frontier_bbs[self.rng.random_range(0..self.frontier_bbs.len())]);
            } else {
                let edges_pass = self.codecov_sess.get_pass::<EdgeCoveragePass>();
                let edges = edges_pass
                    .coverage
                    .iter_covered_keys()
                    .filter(|e| {
                        self.module.functions[e.function as usize]
                            .critical_insn_edges
                            .contains(&(e.from, e.to))
                    })
                    .collect::<Vec<_>>();
                // TODO: focus on frontier edges?
                if !edges.is_empty() {
                    target_edge = Some(edges[self.rng.random_range(0..edges.len())]);
                }
            }
        }

        let fuel_limit = apply_fuellimit.then(|| {
            let scope_per_edge_max_needed_fuel = match target_edge {
                Some(edge) => *self
                    .codecov_sess
                    .get_pass::<EdgeShortestExecutionTracePass>()
                    .coverage
                    .saved_val(&edge),
                None => self
                    .codecov_sess
                    .get_pass::<EdgeShortestExecutionTracePass>()
                    .coverage
                    .iter_saved()
                    .map(|(_edge, &val)| val)
                    .filter(|&x| !x.is_bottom())
                    .map(|x| *x)
                    .max()
                    .unwrap_or(500_000),
            };

            let res = scope_per_edge_max_needed_fuel * 2 + 500_000;
            // bucket the fuel limit to reduce corpus size
            let res = res.next_power_of_two();
            res.min(self.codecov_sess.swarm.instruction_limit.unwrap())
        });
        let memory_limit_pages = 1 << self.rng.random_range(8..16);
        let input_size_limit = *[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 - 1]
            .choose(&mut self.rng)
            .unwrap();

        let mut swarm = SwarmConfig::default();
        swarm.instruction_limit =
            Some(fuel_limit.unwrap_or(self.codecov_sess.swarm.instruction_limit.unwrap()));
        swarm.memory_limit_pages = Some(memory_limit_pages);
        swarm.input_size_limit = Some(input_size_limit);

        let extra_musts_and_avoids = self.rng.random_ratio(5, 10);
        if extra_musts_and_avoids {
            // TODO: evaluate this
            if matches!(self.opts.experiment, Some(Experiment::SwarmFocusEdge)) {
                if let Some(target_edge) = target_edge
                    && !self.init_edges.contains(&target_edge)
                    && self.rng.random_ratio(5, 10)
                {
                    swarm.must_include_edges.insert(target_edge);
                }
                if let Some(target_bb) = target_bb {
                    swarm.must_include_bbs.insert(target_bb);
                }
            }

            // TODO: add extra musts and avoids
        }

        if !swarm.must_include_bbs.is_empty() || !swarm.must_include_edges.is_empty() {
            swarm.discard_short_circuit_coverage = true;
        }

        let mut opts = FeedbackOptions::nothing();
        let FeedbackOptions {
            live_funcs,
            live_bbs,
            live_edges,
            cmpcov_hamming,
            cmpcov_absdist,
            cmpcov_u16dist,
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
            path_hash_func,
            path_hash_edge,
            func_shortest_trace,
            edge_shortest_trace,
            func_longest_trace,
        } = &mut opts;

        // We always enable edge coverage, and edge coverage subsumes function and bb coverage.
        // Function coverage is enabled for the CLI status line.
        *live_funcs = true;
        *live_bbs = false;
        *live_edges = true;

        if self.opts.experiment == Some(Experiment::PassAblation) {
            let pass =
                std::env::var("FUZZER_PASS_ABLATION").expect("FUZZER_PASS_ABLATION must be set");
            opts.activate_from_str(&pass);
        } else if !is_saturated && self.rng.random_ratio(8, 10) {
            let mut light_knobs = [
                &mut *cmpcov_absdist,
                &mut *cmpcov_hamming,
                &mut *func_input_size_color,
                &mut *func_shortest_trace,
                &mut *perffuzz_edge_global,
            ];
            for _ in 0..3 {
                let opt = light_knobs.choose_mut(&mut self.rng).unwrap();
                if **opt {
                    break;
                }
                **opt = true;
            }
        } else {
            let mut all_knobs = [
                &mut *call_value_profile,
                &mut *cmpcov_absdist,
                &mut *cmpcov_hamming,
                &mut *cmpcov_u16dist,
                &mut *perffuzz_func,
                &mut *perffuzz_bb,
                &mut *perffuzz_edge,
                &mut *perffuzz_edge_global,
                &mut *func_rec_depth,
                &mut *func_input_size,
                &mut *func_input_size_cyclic,
                &mut *func_input_size_color,
                &mut *memory_op_value,
                &mut *memory_op_address,
                &mut *memory_store_prev_value,
                &mut *path_hash_func,
                &mut *path_hash_edge,
                &mut *func_shortest_trace,
                &mut *edge_shortest_trace,
                &mut *func_longest_trace,
            ];
            for _ in 0..3 {
                let opt = all_knobs.choose_mut(&mut self.rng).unwrap();
                if **opt {
                    break;
                }
                **opt = true;
            }
        }

        if matches!(self.opts.experiment, Some(Experiment::OnlyEdgeCoverage)) {
            opts = FeedbackOptions::minimal_code_coverage();
            opts.live_edges = false;
        }

        Config {
            passes: OrcPassesGen {
                opts,
                spec: self.module.clone(),
                swarm: swarm.clone(),
                instr_only_funcs: self.coverage_is_saturated().then(|| {
                    let pass = self.codecov_sess.get_pass::<FunctionCoveragePass>();
                    pass.coverage.iter_covered_keys().collect()
                }),
            },
            swarm,
            timeout,
        }
    }

    fn coverage_is_saturated(&self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.start).as_secs_f32() < 5.0 {
            false
        } else {
            now.duration_since(self.start)
                .min(std::time::Duration::from_secs(30))
                < now.duration_since(self.last_func_find).mul_f32(2.)
        }
    }

    fn should_continue(&self) -> bool {
        !self.found_crashes
            && self
                .opts
                .timeout
                .map(|x| self.start.elapsed() < *x)
                .unwrap_or(true)
    }

    fn add_corpus(&mut self, input: &[u8]) -> Option<RunResult> {
        let mut corp = self.corpus.write().unwrap();
        if !corp.insert(input, Instant::now()) {
            return None;
        }
        drop(corp);
        let res = self
            .codecov_sess
            .run_reusable_fresh(input, false, &mut Stats::new());
        if res.novel_coverage_passes.contains(&"funcs") {
            self.last_func_find = Instant::now();
        }
        self.found_crashes |= res.is_crash();
        Some(res)
    }

    fn update_live_coverage(&self) {
        #[cfg(feature = "reports")]
        if let Some(out_path) = self.opts.live_html_coverage.as_ref() {
            crate::cli::cov_html::write_html_cov_report(
                self.module.clone(),
                &self.codecov_sess,
                out_path,
            );
        }
    }

    fn compute_frontier(&self) -> HashSet<Location> {
        let edge_cov = self.codecov_sess.get_pass::<EdgeCoveragePass>();
        let bb_cov = self.codecov_sess.get_pass::<BBCoveragePass>();
        let covered_blocks = bb_cov.coverage.iter_covered_keys().collect::<HashSet<_>>();
        let covered_edges = edge_cov
            .coverage
            .iter_covered_keys()
            .collect::<HashSet<_>>();
        let mut res = HashSet::default();
        for func in &self.module.functions {
            if self.init_funcs.contains(&FuncIdx(func.idx)) {
                continue;
            }
            for &(from, to) in &func.critical_insn_edges {
                let edge = Edge {
                    function: func.idx,
                    from,
                    to,
                };
                let from_bb = Location {
                    function: func.idx,
                    index: func.operator_basic_block[from.i()].0,
                };
                if covered_blocks.contains(&from_bb) && !covered_edges.contains(&edge) {
                    // res.push(edge);
                    res.insert(from_bb);
                }
            }
        }
        res
    }
}

#[derive(Debug)]
pub(crate) struct Config {
    pub swarm: SwarmConfig,
    pub passes: OrcPassesGen,
    pub timeout: std::time::Duration,
}

#[derive(Clone)]
pub(crate) struct OrcPassesGen {
    pub swarm: SwarmConfig,
    pub opts: FeedbackOptions,
    pub spec: Arc<ModuleSpec>,
    pub instr_only_funcs: Option<HashSet<FuncIdx>>,
}

impl std::fmt::Debug for OrcPassesGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrcPassesGen")
            .field("opts", &self.opts)
            .field("spec", &self.spec)
            .field(
                "instr_only_funcs (cnt)",
                &self.instr_only_funcs.as_ref().map(|x| x.len()),
            )
            .finish_non_exhaustive()
    }
}

impl PassesGen for OrcPassesGen {
    fn generate_passes(&self) -> Passes {
        use crate::instrumentation::*;

        let mut passes = Passes::empty();

        let FeedbackOptions {
            live_funcs,
            live_bbs,
            live_edges,
            cmpcov_hamming,
            cmpcov_absdist,
            cmpcov_u16dist,
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

        // We don't really need to add coverage instrumentation to functions
        // that have not been covered yet if it looks like coverage has settled.
        // This reduces compilation time (~ -30%) and improve performance (~ -25%) by reducing bitmap sizes.
        let key_filter = |loc: &Location| match &self.instr_only_funcs {
            Some(x) => x.contains(&FuncIdx(loc.function)),
            None => true,
        };

        add_pass!(live_funcs, FunctionCoveragePass::new(&self.spec, |_| true));
        add_pass!(live_bbs, BBCoveragePass::new(&self.spec, key_filter));
        add_pass!(live_edges, EdgeCoveragePass::new(&self.spec, key_filter));

        macro_rules! add_pass {
            ($cond:expr, $pass:expr) => {
                if $cond {
                    passes.push_kv($pass);
                }
            };
        }

        add_pass!(
            cmpcov_hamming,
            CmpCoveragePass::new(CmpCovKind::Hamming, &self.spec, key_filter)
        );
        add_pass!(
            cmpcov_absdist,
            CmpCoveragePass::new(CmpCovKind::AbsDist, &self.spec, key_filter)
        );
        add_pass!(cmpcov_u16dist, CmpDistU16Pass::new(&self.spec, key_filter));

        add_pass!(
            func_input_size,
            InputSizePass::new(InputComplexityMetric::Size, &self.spec, key_filter)
        );
        add_pass!(
            func_input_size_cyclic,
            InputSizePass::new(InputComplexityMetric::ByteDiversity, &self.spec, key_filter)
        );
        add_pass!(
            func_input_size_color,
            InputSizePass::new(InputComplexityMetric::DeBruijn, &self.spec, key_filter)
        );

        add_pass!(
            perffuzz_func,
            PerffuzzFunctionPass::new(&self.spec, key_filter)
        );
        add_pass!(perffuzz_bb, PerffuzzBBPass::new(&self.spec, key_filter));
        add_pass!(
            perffuzz_edge,
            EdgeHitsInAFunctionPass::new(&self.spec, key_filter)
        );
        add_pass!(
            perffuzz_edge_global,
            PerffuzzEdgePass::new(&self.spec, key_filter)
        );
        add_pass!(
            func_rec_depth,
            FunctionRecursionDepthPass::new(&self.spec, key_filter)
        );

        add_pass!(
            memory_op_value,
            MemoryLoadValRangePass::new(&self.spec, key_filter)
        );
        add_pass!(
            memory_op_value,
            MemoryStoreValRangePass::new(&self.spec, key_filter)
        );
        add_pass!(
            memory_op_address,
            MemoryOpAddressRangePass::new(&self.spec, key_filter)
        );
        add_pass!(
            memory_store_prev_value,
            MemoryStorePrevValRangePass::new(&self.spec, key_filter)
        );

        add_pass!(
            call_value_profile,
            CallParamsRangePass::new(&self.spec, key_filter)
        );
        add_pass!(
            call_value_profile,
            CallParamsSetPass::new(&self.spec, key_filter)
        );
        add_pass!(
            call_value_profile,
            GlobalsRangePass::new(&self.spec, key_filter)
        );

        add_pass!(
            func_shortest_trace,
            FunctionShortestExecutionTracePass::new(&self.spec, key_filter)
        );
        add_pass!(
            edge_shortest_trace,
            EdgeShortestExecutionTracePass::new(&self.spec, key_filter)
        );
        add_pass!(
            func_longest_trace,
            FunctionLongestExecutionTracePass::new(&self.spec, key_filter)
        );

        macro_rules! add_pass {
            ($cond:expr, $pass:expr) => {
                if $cond {
                    passes.push_hash($pass);
                }
            };
        }

        add_pass!(
            path_hash_func,
            FuncPathHashPass::new(&self.spec, key_filter)
        );
        add_pass!(
            path_hash_edge,
            EdgePathHashPass::new(&self.spec, key_filter)
        );

        if !self.swarm.avoid_functions.is_empty()
            || !self.swarm.avoid_edges.is_empty()
            || !self.swarm.must_include_edges.is_empty()
            || !self.swarm.must_include_functions.is_empty()
        {
            passes.push_erased(SwarmShortCircuitPass::new(self.swarm.clone()));
        }

        passes
    }
}
