use std::{
    ops::Deref,
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::Parser;
use humantime::Duration;

#[derive(Debug, Clone, Parser)]
pub(crate) struct GeneralOpts {
    // Module under test
    pub program: PathBuf,
    // Load initial corpus from this path.
    #[clap(long)]
    pub seed_dir: Option<String>,
    // Output finds to this path.
    #[clap(long)]
    pub out_dir: Option<String>,
    // Set both seed_dir and out_dir
    #[clap(long, conflicts_with = "seed_dir", conflicts_with = "out_dir")]
    pub dir: Option<String>,
    // Sets corpus dir to ~/.local/share/wasmfuzz/autosave-corpi/$target
    #[clap(short, long, conflicts_with = "dir")]
    pub autosave: bool,
    // Limit input size, up to 65535
    // Note: libfuzzer defaults to 4k
    #[clap(long, default_value = "65535")]
    pub input_size_limit: usize,
}

impl GeneralOpts {
    pub(crate) fn corpus_dir(&self) -> Option<PathBuf> {
        if self.autosave {
            let mut program = PathBuf::from(&self.program);
            program.set_extension("");
            let program = program.file_name().unwrap();
            let mut path = dirs::data_dir().expect("not sure where to put autosave corpus");
            path.push("wasmfuzz");
            path.push("autosave-corpi");
            path.push(program);
            std::fs::create_dir_all(&path).unwrap();
            Some(path.to_str().unwrap().to_owned().into())
        } else {
            self.dir.as_deref().map(Into::into)
        }
    }

    pub(crate) fn seed_dir(&self) -> Option<PathBuf> {
        self.seed_dir
            .as_deref()
            .map(Into::into)
            .or_else(|| self.corpus_dir())
    }

    pub(crate) fn out_dir(&self) -> Option<PathBuf> {
        self.out_dir
            .as_deref()
            .map(Into::into)
            .or_else(|| self.corpus_dir())
    }
}

#[derive(Debug, Parser, Clone)]
pub(crate) struct InstrumentationOpts {
    // instrumentation knobs
    #[clap(long, default_value = "true")]
    pub cov_funcs: FlagBool,
    #[clap(long, default_value = "false")]
    pub cov_bbs: FlagBool,
    #[clap(long, default_value = "true")]
    pub cov_edges: FlagBool,
    #[clap(long, default_value = "true")]
    pub cmpcov_hamming: FlagBool,
    #[clap(long, default_value = "true")]
    pub cmpcov_absdist: FlagBool,
    #[clap(long, default_value = "false")]
    pub cmpcov_u16dist: FlagBool,
    #[clap(long, default_value = "true")]
    pub perffuzz_func: FlagBool,
    #[clap(long, default_value = "false")]
    pub perffuzz_bb: FlagBool,
    #[clap(long, default_value = "false")]
    pub perffuzz_edge_local: FlagBool,
    #[clap(long, default_value = "false")]
    pub perffuzz_edge: FlagBool,
    #[clap(long, default_value = "false")]
    pub func_rec_depth: FlagBool,
    #[clap(long, default_value = "false")]
    pub call_value_profile: FlagBool,
    #[clap(long, default_value = "true")]
    pub cov_func_input_size: FlagBool,
    #[clap(long, default_value = "false")]
    pub cov_func_input_size_cyclic: FlagBool,
    #[clap(long, default_value = "false")]
    pub cov_func_input_size_color: FlagBool,
    #[clap(long, default_value = "false")]
    pub cov_memory_op_value: FlagBool,
    #[clap(long, default_value = "false")]
    pub cov_memory_op_address: FlagBool,
    #[clap(long, default_value = "false")]
    pub cov_memory_store_prev_value: FlagBool,
    #[clap(long, default_value = "false")]
    pub path_hash_func: FlagBool,
    #[clap(long, default_value = "false")]
    pub path_hash_edge: FlagBool,
    #[clap(long, default_value = "false")]
    pub func_shortest_trace: FlagBool,
    #[clap(long, default_value = "false")]
    pub edge_shortest_trace: FlagBool,
    #[clap(long, default_value = "false")]
    pub func_longest_trace: FlagBool,
}

impl InstrumentationOpts {
    pub(crate) fn to_feedback_opts(&self) -> crate::jit::FeedbackOptions {
        let Self {
            cov_funcs,
            cov_bbs,
            cov_edges,
            cmpcov_hamming,
            cmpcov_absdist,
            cmpcov_u16dist,
            perffuzz_func,
            perffuzz_bb,
            perffuzz_edge_local,
            perffuzz_edge,
            func_rec_depth,
            call_value_profile,
            cov_func_input_size,
            cov_func_input_size_cyclic,
            cov_func_input_size_color,
            cov_memory_op_value,
            cov_memory_op_address,
            cov_memory_store_prev_value,
            path_hash_func,
            path_hash_edge,
            func_shortest_trace,
            edge_shortest_trace,
            func_longest_trace,
        } = self;
        crate::jit::FeedbackOptions {
            live_funcs: **cov_funcs,
            live_bbs: **cov_bbs,
            live_edges: **cov_edges,
            cmpcov_hamming: **cmpcov_hamming,
            cmpcov_absdist: **cmpcov_absdist,
            cmpcov_u16dist: **cmpcov_u16dist,
            perffuzz_func: **perffuzz_func,
            perffuzz_bb: **perffuzz_bb,
            perffuzz_edge: **perffuzz_edge_local,
            perffuzz_edge_global: **perffuzz_edge,
            func_rec_depth: **func_rec_depth,
            call_value_profile: **call_value_profile,
            func_input_size: **cov_func_input_size,
            func_input_size_cyclic: **cov_func_input_size_cyclic,
            func_input_size_color: **cov_func_input_size_color,
            memory_op_value: **cov_memory_op_value,
            memory_op_address: **cov_memory_op_address,
            memory_store_prev_value: **cov_memory_store_prev_value,
            path_hash_func: **path_hash_func,
            path_hash_edge: **path_hash_edge,
            func_shortest_trace: **func_shortest_trace,
            edge_shortest_trace: **edge_shortest_trace,
            func_longest_trace: **func_longest_trace,
        }
    }
}

#[derive(Debug, Parser, Clone)]
pub(crate) struct ScheduleOpts {
    // timing knobs
    #[clap(long, default_value = "65s")]
    pub cmin_interval: Duration,
    #[clap(long, default_value = "60s")]
    pub stats_interval: Duration,
    #[clap(long, default_value = "2s")] // was: 100ms
    pub bus_poll_interval: Duration,
    #[clap(long)]
    pub timeout: Option<Duration>,
    #[clap(long)]
    pub idle_timeout: Option<Duration>,
    #[clap(long)]
    pub timeout_steps: Option<u64>,
}

#[derive(Debug, Parser, Clone)]
pub(crate) struct StrategyOpts {
    #[clap(long, default_value = "true")]
    pub(crate) use_cmplog: FlagBool,
    #[clap(long, default_value = "true")]
    pub mopt: FlagBool,
    #[clap(long, default_value = "0")]
    pub corpus_drop_pct: u64,
    #[clap(long, default_value = "0")]
    pub corpus_cmin_drop_pct: u64,
    #[clap(long, default_value = "5")]
    pub cmin_after_corpus_additions: u64,
    #[clap(long, default_value = "true")]
    pub exhaustive_stage: FlagBool,
    #[clap(long, default_value = "false")]
    pub use_concolic: FlagBool,
    #[clap(long, value_parser=cli_parse_humancount, default_value="750m")]
    pub instruction_limit: Option<u64>,
    // Reset VMContext's memory for deterministic (re-)execution
    #[clap(long, default_value = "true")]
    pub run_from_snapshot: FlagBool,
    #[clap(long, default_value = "false")]
    pub fuzz_through_crashes: FlagBool,

    #[clap(long, default_value = "false")]
    pub ignore_bus_inputs: FlagBool,
}

impl Default for StrategyOpts {
    fn default() -> Self {
        Self::parse_from(vec!["wasmfuzz"])
    }
}

// TODO: use doc comments? looks kinda bad in --help
#[derive(Debug, Parser, Clone)]
pub(crate) struct FuzzOpts {
    #[clap(flatten)]
    pub g: GeneralOpts,
    // instrumentation knobs
    #[clap(flatten)]
    pub i: InstrumentationOpts,
    // timing knobs
    #[clap(flatten)]
    pub t: ScheduleOpts,
    // other fuzzing knobs
    #[clap(flatten)]
    pub x: StrategyOpts,

    #[clap(long)]
    pub verbose: bool,
    #[clap(long)]
    pub verbose_corpus: bool,
    #[clap(long)]
    pub debug_trace: bool,
    #[clap(long, default_value = "1-1")]
    pub cores: String,
    // Delay thread startup in multi-core setting. Can help with peak memory usage / tames the thundering herd.
    #[clap(long, default_value = "3s")]
    pub stagger_cores: Duration,
    #[clap(long)]
    pub rng_seed: Option<u64>,

    #[clap(skip)]
    pub thread_name: Option<String>,
}

impl FuzzOpts {
    pub(crate) fn resolve_corpus_dir(dir: String, program: &Path) -> PathBuf {
        if dir == "auto" {
            let opts = Self::parse_from(vec![
                "wasmfuzz-fuzz",
                program.to_str().unwrap(),
                "--autosave",
            ]);
            opts.g.corpus_dir().unwrap()
        } else {
            dir.into()
        }
    }
}

// https://github.com/clap-rs/clap/issues/1649
#[derive(Clone, Debug)]
pub(crate) struct FlagBool(bool);
impl FromStr for FlagBool {
    type Err = <bool as FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}
impl Deref for FlagBool {
    type Target = bool;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<bool> for FlagBool {
    fn from(val: bool) -> Self {
        Self(val)
    }
}

/// `clap` argument parser that allows 42m for 42_000_000
fn cli_parse_humancount(count: &str) -> Result<u64, std::num::ParseIntError> {
    let sizes = [
        ("k", 1_000),
        ("m", 1_000_000),
        ("b", 1_000_000_000),
        ("g", 1_000_000_000),
    ];
    let count = count.to_lowercase();
    for (suffix, mult) in sizes {
        if count.ends_with(suffix) {
            let count = &count[..count.len() - suffix.len()];
            return Ok(count.parse::<u64>()?.checked_mul(mult).unwrap());
        }
    }
    count.parse::<u64>()
}
