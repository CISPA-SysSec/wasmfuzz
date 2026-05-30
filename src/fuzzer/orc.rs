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
    #[clap(flatten)]
    pub x: super::opts::StrategyOpts,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub(crate) enum Experiment {
    UseBusInputs,
    SwarmFocusEdge,
    Snapshot,
    OnlyEdgeCoverage,
    PassAblation,

    /// Run with LOD options entirely disabled (raw libafl mutator only).
    /// Useful as the "no-structured-mutation" anchor.
    LodDisable,
    /// Seed the worker corpus with the LOD engine's dummy byte string and
    /// nothing else; structure-only-seed A/B.
    LodDummyOnly,
    /// Drive the LOD engine via `generate(seed)` only (no `mutate`); pure-
    /// generation A/B against the default mutate-or-splice loop.
    LodGenerateOnly,
    /// Disable LOD-tier switching (`lod_switch_inv = 0`). Stays at one tier
    /// per run. Kept as a structural-A/B knob worth re-running periodically.
    LodNoLevelSwitching,
    /// Archival rollback baseline: the *previous* `LodBest` — cmplog-fresh-best
    /// + cap_per_type=256 + `expire_corpus_after=10m`, *without* the H30B splice
    /// doubling. Opts out of the splice base only (LOD-side); runs 10m host-side.
    /// Re-run alongside the new best each post-promotion campaign to confirm the
    /// promotion stays ahead. Pre-cmplog / 30m history recoverable from
    /// `git log -p orc.rs`.
    LodOld,
    /// Current best config. As of 2026-05-30 (H30B): cap_per_type=256 +
    /// cmplog-fresh at 0.25 + `splice`/`splice_minor`/`splice_append` doubled
    /// (LOD-side) + `expire_corpus_after=10m` (host-side, applied via
    /// `apply_host_opts`). Everything except `LodOld` / `LodDisable` layers
    /// on top.
    LodBest,
    /// Disable LibAFL's MOpt mutator on the interleaved byte-mutation branch
    /// (`opts.x.mopt = false`). bdKp: +5.40 % mean (8 rank-1 wins); WrQ7:
    /// -0.35 % (1 rank-1, two large-Â12 near-miss regressions) — target-mix
    /// sensitive, kept for a third confirming pass on the post-promotion base.
    LodNoMopt,
    /// Looser corpus minimization: `--cmin-after-corpus-additions 20`
    /// (default 5). bdKp: +2.92 % mean; WrQ7: +0.86 %; mHE0: -0.62 % mean
    /// with one BH-significant per-target loss on `libwebp` (Â12=0.281
    /// q=0.018). Retired after the 3rd pass; archival anchor.
    LodCminLoose,
    /// Bracket-from-below probe on the 2026-05-26-promoted
    /// `expire_corpus_after = 10m`: shorten to 5m. mHE0: -0.46 % mean,
    /// 13/23 better, no BH cells — combined with 7rtA's 30m → 10m result,
    /// the dial is converged at 10m from both sides. Retired.
    LodFresherCorpus,
    /// Tilt `KindWeights` toward byte-leaf operations (`bit_flip_bytes`,
    /// `bit_flip_byte_arr`, `interesting_bytes`/`_byte_arr`, `byte_mutate`,
    /// `byte_resize`, `byte_splice` all doubled). Three campaigns (08986d:
    /// -1.16 % mean / 5 rank-1; 4976d4: +0.24 % / 6 rank-1; rePZ: -0.13 % /
    /// 5 rank-1) show a recurring byte-friendly per-target cluster (`libpng`,
    /// `zune-jpeg`, `image-ico`, `libwebp`, `vorbis`, `lewton-ogg`) without
    /// durable mean uplift. Retired from the uniform rotation after the 3rd
    /// mean-null; the cluster is per-target-schedule input, not a global knob.
    /// Archival anchor.
    LodByteHeavy,
    /// Opposite-direction probe to [`LodByteHeavy`]: boost structural ops
    /// (`variant_switch`, `list_pop`/`_append`/`_dup`/`_shuffle`, `splice`/
    /// `_minor`/`_append`, `option_toggle`). rePZ: +1.94 % mean / 9 rank-1;
    /// H30B (pass 2): +2.95 % mean / 7 rank-1 (best mean-rank) — reconfirmed.
    /// Decomposition showed the win is split: the splice half carried the only
    /// BH-significant cell (no regressions) and was promoted into the base; the
    /// reshape half carries the openjpeg/x509 losses. Archival — its splice
    /// doubling now compounds the base to splice×4.
    LodStructHeavy,
    /// AFL-style havoc stacking: `MutationConfig::stack = StackProfile::HAVOC`
    /// (Geometric{p:0.5, max:8}) — replaces the default `Fixed(1)`. rePZ:
    /// +0.06 % mean, mean Â12 0.508, no large-effect cell either direction —
    /// genuinely null. Combined with 08986d's lighter Geometric{0.3,4}
    /// (`stack-geom-light`, -1.25 %), the stack-profile dial is bracketed from
    /// both sides (light negative, heavy flat) and `Fixed(1)` is confirmed.
    /// Retired; archival anchor.
    LodStackHavoc,
    /// Splice half of [`Experiment::LodStructHeavy`]: `splice` / `splice_minor`
    /// / `splice_append` doubled. H30B: +2.41 % mean, 16/23 better, mean Â12 0.54
    /// (highest), sole BH-significant cell jxl-rs (Â12 0.733 q=0.045), no
    /// regressions — the clean productive half. **Promoted into the base block
    /// 2026-05-30.** This arm now layers a *second* doubling on top of the base
    /// (splice×4); reused as the bracket-from-above splice probe.
    LodSpliceHeavy,
    /// Reshape half of [`Experiment::LodStructHeavy`]: `variant_switch`,
    /// `list_pop`/`_append`, `list_dup`/`_shuffle` (×3, they start at 0.5),
    /// `option_toggle` doubled. H30B: +1.97 % mean / 14 better but carries the
    /// regression cluster (openjpeg Â12 0.35, x509-certreq 0.386) — the weaker
    /// half. On the post-splice-promotion base it now equals the whole
    /// `LodStructHeavy` (splice×2 + reshape); re-run as the "does reshape add
    /// net value over splice-alone" probe.
    LodVariantHeavy,
}
impl Experiment {
    pub fn is_lod(&self) -> bool {
        format!("{self:?}").starts_with("Lod")
    }

    /// True when the worker should snapshot per-testcase `CmplogStore` metadata
    /// and thread it into `MutationInputs::cmplog`. After the 2026-05-23
    /// rebaseline this is "everything that layers on `LodBest`" — derived
    /// directly from the resulting `cmplog_fresh_prob`.
    pub fn wants_cmplog(self) -> bool {
        self.lod_config().mutation.cmplog_fresh_prob > 0.0
    }

    /// True when cross-worker bus imports should be enabled. LOD experiments
    /// run with the bus off (see `fuzzer/mod.rs::fuzz`); only the dedicated
    /// `UseBusInputs` probe opts in.
    pub fn wants_bus(self) -> bool {
        matches!(self, Experiment::UseBusInputs)
    }

    /// Apply host-side (non-LOD) knobs to `CliOpts` before the orchestrator
    /// and workers spawn. Counterpart to `lod_config` for knobs that live
    /// outside `EngineConfig` (libafl mutator stack, corpus eviction, etc.).
    /// Called once from `fuzzer/mod.rs::fuzz`.
    pub fn apply_host_opts(self, opts: &mut CliOpts) {
        // Layered host-side base for current best: `expire_corpus_after = 10m`
        // on top of cmplog-fresh-best. Only `LodDisable` opts out now; `LodOld`
        // reproduces the *previous* best (which also ran 10m), serving as the
        // post-splice-promotion rollback baseline.
        if self.is_lod() && !matches!(self, Experiment::LodDisable) {
            opts.expire_corpus_after = "10m".parse().unwrap();
        }
        match self {
            Experiment::LodNoMopt => {
                opts.x.mopt = false.into();
            }
            Experiment::LodCminLoose => {
                opts.x.cmin_after_corpus_additions = 20;
            }
            Experiment::LodFresherCorpus => {
                opts.expire_corpus_after = "5m".parse().unwrap();
            }
            _ => {}
        }
    }

    pub fn lod_config_for(exp: Option<Experiment>) -> lod::EngineConfig {
        exp.map(Experiment::lod_config).unwrap_or_default()
    }

    fn lod_config(self) -> lod::EngineConfig {
        use lod::EngineConfig;
        let mut cfg = EngineConfig::default();
        // Experiments layer on top of the current best-known config:
        //   LOD-side:  cap_per_type = 256, cmplog_fresh_prob = 0.25,
        //              splice/splice_minor/splice_append doubled (H30B promotion).
        //   host-side: expire_corpus_after = 10m (see `apply_host_opts`).
        // `LodDisable` opts out entirely. `LodOld` reproduces the *previous*
        // best (cmplog-fresh + cap256 + 10m, pre-splice) so it opts out of the
        // splice doubling only — the post-promotion rollback baseline.
        if !matches!(self, Experiment::LodDisable) {
            cfg.corpus.cap_per_type = 256;
            cfg.mutation.cmplog_fresh_prob = 0.25;
        }
        // Splice-heavy promoted 2026-05-30 (H30B): +2.41 % mean, 16/23 better,
        // the campaign's sole BH-significant cell (jxl-rs Â12 0.733 q=0.045),
        // highest mean Â12, no per-target regressions. `LodOld` reproduces the
        // pre-splice baseline and opts out.
        if !matches!(self, Experiment::LodDisable | Experiment::LodOld) {
            let w = &mut cfg.mutation.weights;
            w.splice *= 2.0;
            w.splice_minor *= 2.0;
            w.splice_append *= 2.0;
        }
        match self {
            Experiment::LodNoLevelSwitching => {
                cfg.lod_switch_inv = 0;
            }
            Experiment::LodOld
            | Experiment::LodBest
            | Experiment::LodNoMopt
            | Experiment::LodCminLoose
            | Experiment::LodFresherCorpus => {
                // Pure host-knob layered probes / archival aliases; LOD config
                // is the cmplog-fresh-best base from above.
            }
            Experiment::LodByteHeavy => {
                let w = &mut cfg.mutation.weights;
                w.bit_flip_bytes *= 2.0;
                w.bit_flip_byte_arr *= 2.0;
                w.interesting_bytes *= 2.0;
                w.interesting_byte_arr *= 2.0;
                w.byte_mutate *= 2.0;
                w.byte_resize *= 2.0;
                w.byte_splice *= 2.0;
            }
            Experiment::LodStructHeavy => {
                let w = &mut cfg.mutation.weights;
                w.variant_switch *= 2.0;
                w.list_pop *= 2.0;
                w.list_append *= 2.0;
                w.list_dup *= 3.0;
                w.list_shuffle *= 3.0;
                w.splice *= 2.0;
                w.splice_minor *= 2.0;
                w.splice_append *= 2.0;
                w.option_toggle *= 2.0;
            }
            Experiment::LodStackHavoc => {
                cfg.mutation.stack = lod::StackProfile::HAVOC;
            }
            Experiment::LodSpliceHeavy => {
                let w = &mut cfg.mutation.weights;
                w.splice *= 2.0;
                w.splice_minor *= 2.0;
                w.splice_append *= 2.0;
            }
            Experiment::LodVariantHeavy => {
                let w = &mut cfg.mutation.weights;
                w.variant_switch *= 2.0;
                w.list_pop *= 2.0;
                w.list_append *= 2.0;
                w.list_dup *= 3.0;
                w.list_shuffle *= 3.0;
                w.option_toggle *= 2.0;
            }
            Experiment::LodDisable | Experiment::LodDummyOnly | Experiment::LodGenerateOnly => {
                // no knobs, see worker.rs / orc.rs corpus seeding
            }

            Experiment::UseBusInputs
            | Experiment::Snapshot
            | Experiment::SwarmFocusEdge
            | Experiment::OnlyEdgeCoverage
            | Experiment::PassAblation => {
                // non-lod experiments
            }
        }
        cfg
    }
}

#[derive(Clone)]
pub(crate) struct OrchestratorHandle {
    // pub Arc<Mutex<Orchestrator>>
    chan: mpsc::Sender<(OrcMessage, mpsc::SyncSender<OrcMessage>)>,
    corpus: Arc<RwLock<SharedCorpus>>,
    metrics: Arc<super::metrics::Accumulator>,
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
        super::metrics::init_session();
        let metrics = Arc::new(super::metrics::Accumulator::default());

        let metrics_ = metrics.clone();
        let _thread_handle = std::thread::Builder::new()
            .stack_size(32 << 20) // TODO: look into why generated code doesn't probe the stack any more?
            .name("orchestrator".to_owned())
            .spawn(move || {
                let mut orc = Orchestrator::new(module, opts, corpus_, metrics_);
                loop {
                    let Ok((req, tx)) = rx.recv() else {
                        break;
                    };
                    let resp = match req {
                        OrcMessage::ReqSuggest => OrcMessage::RespSuggest(orc.suggest().into()),
                        OrcMessage::ReqShouldContinue => {
                            OrcMessage::RespShouldContinue(orc.should_continue())
                        }
                        OrcMessage::ReqReportFinds(finds) => {
                            let mut update_live_coverage = false;
                            let total = finds.len();
                            let mut saved = 0u64;
                            for input in finds {
                                let (res, wrote_to_disk) = orc.report_find(&input);
                                update_live_coverage |=
                                    res.map(|x| x.novel_coverage).unwrap_or(false);
                                saved += wrote_to_disk as u64;
                            }
                            if saved > 0 {
                                let dir = orc
                                    .opts
                                    .g
                                    .out_dir()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "<unset>".into());
                                eprintln!(
                                    "report_finds: saved {saved}/{total} new inputs to {dir}"
                                );
                            }
                            let mut corpus = orc.corpus.write().unwrap();
                            corpus.cull_and_update_weights();
                            drop(corpus);
                            if update_live_coverage {
                                orc.update_live_coverage();
                                orc.frontier_bbs = orc.compute_frontier().into_iter().collect();
                            }
                            orc.push_orc_edges_metrics();
                            OrcMessage::RespOk
                        }
                        OrcMessage::ReqShutdown => {
                            tx.send(OrcMessage::RespOk).unwrap();
                            break;
                        }
                        OrcMessage::ReqLoadCorpus(corpus) => {
                            let _ = orc.load_corpus(&corpus);
                            orc.update_live_coverage();
                            orc.push_orc_edges_metrics();
                            OrcMessage::RespOk
                        }
                        _ => OrcMessage::RespInvalid,
                    };
                    tx.send(resp).unwrap();
                }
            });

        Self {
            chan: tx,
            corpus,
            metrics,
        }
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

    /// Shared metrics accumulator workers merge their [`Stats`] deltas into
    /// and periodically dump.
    pub fn metrics(&self) -> Arc<super::metrics::Accumulator> {
        self.metrics.clone()
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

    /// Returns `(newly_added, wrote_to_disk)`. `wrote_to_disk` is only ever
    /// `true` when the input was newly added AND `disk_path` was set AND no
    /// file of that hash already existed.
    fn insert(&mut self, input: &[u8], now: Instant) -> (bool, bool) {
        if let Some(e) = self.entries.get_mut(input) {
            e.last_seen_used = now;
            return (false, false);
        }
        self.entries.insert(
            input.to_vec().into_boxed_slice(),
            Entry {
                input: input.to_vec().into_boxed_slice().into(),
                last_seen_used: now,
                weight: 1.0,
            },
        );

        let mut wrote_to_disk = false;
        if let Some(disk_path) = self.disk_path.as_ref() {
            let p = Self::get_inp_path(disk_path, input);
            if !p.is_file() {
                let _ = std::fs::create_dir_all(disk_path);
                let _ = std::fs::write(&p, input);
                wrote_to_disk = true;
            }
        }
        (true, wrote_to_disk)
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
    lod_options: Vec<&'static str>,
    metrics: Arc<super::metrics::Accumulator>,
}

impl Orchestrator {
    fn new(
        module: Arc<ModuleSpec>,
        opts: CliOpts,
        corpus: Arc<RwLock<SharedCorpus>>,
        metrics: Arc<super::metrics::Accumulator>,
    ) -> Self {
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
        let mut lod_options = if opts.experiment.is_some_and(|x| x.is_lod()) {
            assert!(opts.g.lod.is_none());
            let results = lod::guess_engines(|bytes: &[u8]| -> Vec<bool> {
                use crate::instrumentation::CodeCovInstrumentationPass;
                codecov_sess.reset_pass_coverage();
                let _ = codecov_sess.run_reusable_fresh(bytes, true, &mut Stats::default());
                codecov_sess
                    .get_pass::<EdgeCoveragePass>()
                    .coverage()
                    .saved
                    .iter()
                    .by_vals()
                    .collect()
            });
            assert!(
                !results.is_empty(),
                "lod experiment but no engines detected"
            );
            results
        } else if let Some(engine) = &opts.g.lod {
            let engine = Box::leak(Box::new(engine.clone()));
            vec![engine.as_str()]
        } else {
            Vec::new()
        };
        if matches!(opts.experiment, Some(Experiment::LodDisable)) {
            lod_options.clear();
        }
        if matches!(opts.experiment, Some(Experiment::LodDummyOnly)) {
            let mut corpus = corpus.write().unwrap();
            for option in lod_options.drain(..) {
                if let Some(dummy_bytes) = lod::get_dummy_bytes(option) {
                    let _ = corpus.insert(&dummy_bytes, Instant::now());
                }
            }
        }

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
            lod_options,
            metrics,
        }
    }

    fn push_orc_edges_metrics(&self) {
        if let Some(edges) = self.codecov_sess.get_edge_cov() {
            self.metrics.update_orc_edges(edges);
        }
    }

    pub fn load_corpus(&mut self, inputs: &[Vec<u8>]) -> Result<(), ()> {
        let mut saved = 0u64;
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
            let (res, wrote_to_disk) = self.add_corpus(input);
            saved += wrote_to_disk as u64;
            if let Some(res) = res
                && res.is_crash()
                && !*self.opts.x.fuzz_through_crashes
            {
                eprintln!("load_corpus with crashing input! {res:?}");
                return Err(());
            }
        }
        if !inputs.is_empty() {
            let edges = self.codecov_sess.get_edge_cov().unwrap_or(0);
            let saved_suffix = match self.opts.g.out_dir() {
                Some(p) if saved > 0 => format!(", saved {saved} to {}", p.display()),
                _ => String::new(),
            };
            eprintln!(
                "done loading: {} entries [edges: {edges:>5}]{saved_suffix}",
                inputs.len(),
            );
        }
        Ok(())
    }

    /// Returns `(maybe_run_result, wrote_to_disk)`. `wrote_to_disk` is set if
    /// either the corpus insert created a file, or this method re-created one
    /// that had been deleted out from under us.
    pub fn report_find(
        &mut self,
        /*config: &Config,*/ input: &[u8],
    ) -> (Option<RunResult>, bool) {
        // TODO: apply some kind of bandit on config?
        let (res, mut wrote_to_disk) = self.add_corpus(input);

        if let Some(path) = self.opts.g.out_dir() {
            let mut inp_path = path.clone();
            let inphash = md5::compute(input);
            inp_path.push(format!("{inphash:x}"));
            if !inp_path.is_file() {
                let _ = std::fs::create_dir_all(path);
                let _ = std::fs::write(&inp_path, input);
                wrote_to_disk = true;
            }
        }

        (res, wrote_to_disk)
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
            if self.opts.experiment == Some(Experiment::PassAblation) {
                let pass = std::env::var("FUZZER_PASS_ABLATION")
                    .expect("FUZZER_PASS_ABLATION must be set");
                if pass != "baseline" {
                    opts.activate_from_str(&pass);
                }
            } else {
                opts.cmpcov_hamming = true;
                if self.config_epoch > 0 {
                    opts.edge_shortest_trace = true;
                }
            }
            return Config {
                lod: None,
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
        let memory_limit_pages = 1 << self.rng.random_range(7..13); // 2^13 pages is 512 MB
        let input_size_limit = *[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 - 1]
            .choose(&mut self.rng)
            .unwrap();

        let mut swarm = SwarmConfig::default();
        swarm.instruction_limit =
            Some(fuel_limit.unwrap_or(self.codecov_sess.swarm.instruction_limit.unwrap()));
        swarm.memory_limit_pages = self.rng.random_ratio(9, 10).then_some(memory_limit_pages);
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

        let mut opts = FeedbackOptions::minimal_code_coverage();
        // We always enable edge coverage, and edge coverage subsumes function and bb coverage.
        // Function coverage is enabled for the CLI status line.
        opts.live_bbs = false;
        // Only for grammar experiment for now
        opts.func_input_size_custom = self.opts.g.lod.is_some();

        let FeedbackOptions {
            live_funcs: _,
            live_bbs: _,
            live_edges: _,
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
            func_input_size_custom: _,
            memory_op_value,
            memory_op_address,
            memory_store_prev_value,
            path_hash_func,
            path_hash_edge,
            func_shortest_trace,
            edge_shortest_trace,
            func_longest_trace,
        } = &mut opts;

        if self.opts.experiment == Some(Experiment::PassAblation) {
            let pass =
                std::env::var("FUZZER_PASS_ABLATION").expect("FUZZER_PASS_ABLATION must be set");
            if pass != "baseline" {
                opts.activate_from_str(&pass);
            }
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
            // TODO: update this with perf, noisyness data from evaluation
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
            opts.live_bbs = false;
        }

        let mut lod = None;
        if self.rng.random_ratio(7, 10) {
            lod = self
                .lod_options
                .choose(&mut self.rng)
                .map(|x| x.to_string());
        }

        Config {
            lod,
            passes: OrcPassesGen {
                opts,
                spec: self.module.clone(),
                swarm: swarm.clone(),
                instr_only_funcs: self.coverage_is_saturated().then(|| {
                    let pass = self.codecov_sess.get_pass::<FunctionCoveragePass>();
                    pass.coverage.iter_covered_keys().collect()
                    // TODO: possibly only instrument functions/edges in the frontier?
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
        (!self.found_crashes || *self.opts.x.fuzz_through_crashes)
            && self
                .opts
                .timeout
                .map(|x| self.start.elapsed() < *x)
                .unwrap_or(true)
    }

    /// Returns `(maybe_run_result, wrote_to_disk)`. The run result is `None`
    /// when the input was already in the corpus.
    fn add_corpus(&mut self, input: &[u8]) -> (Option<RunResult>, bool) {
        let mut corp = self.corpus.write().unwrap();
        let (newly_added, wrote_to_disk) = corp.insert(input, Instant::now());
        if !newly_added {
            return (None, false);
        }
        drop(corp);
        let fuzzing = *self.opts.x.fuzz_through_crashes;
        let res = self
            .codecov_sess
            .run_reusable_fresh(input, fuzzing, &mut Stats::new());
        if res.novel_coverage_passes.contains(&"funcs") {
            self.last_func_find = Instant::now();
        }
        self.found_crashes |= res.is_crash();
        (Some(res), wrote_to_disk)
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
    pub lod: Option<String>,
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
            func_input_size_custom,
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
            func_input_size_custom,
            InputSizePass::new(InputComplexityMetric::Custom, &self.spec, key_filter)
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
