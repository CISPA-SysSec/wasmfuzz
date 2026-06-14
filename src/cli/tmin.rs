use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use rand::RngCore;

use bitvec::boxed::BitBox;

use crate::{
    instrumentation::EdgeCoveragePass,
    ir::ModuleSpec,
    jit::{FeedbackOptions, JitFuzzingSession, RunResult, Stats, module::TrapKind},
};

struct TminOracle {
    target_edges: BitBox,
    initial_crashed: bool,
    initial_timeout: bool,
}

impl TminOracle {
    fn new(sess: &JitFuzzingSession, initial_res: &RunResult) -> Self {
        Self {
            target_edges: sess.get_pass::<EdgeCoveragePass>().coverage.saved.clone(),
            initial_crashed: initial_res.is_crash(),
            initial_timeout: initial_res
                .trap_kind
                .as_ref()
                .is_some_and(|x| matches!(x, TrapKind::OutOfFuel(_))),
        }
    }

    fn edge_count(&self) -> usize {
        self.target_edges.count_ones()
    }

    fn accepts(&self, sess: &mut JitFuzzingSession, stats: &mut Stats, candidate: &[u8]) -> bool {
        sess.reset_pass_coverage();
        let res = sess.run_reusable(candidate, true, stats);

        if self.initial_crashed {
            res.is_crash()
        } else {
            sess.get_pass::<EdgeCoveragePass>().coverage.saved == self.target_edges
                && (!self.initial_timeout
                    || res
                        .trap_kind
                        .as_ref()
                        .is_some_and(|x| matches!(x, TrapKind::OutOfFuel(_))))
        }
    }
}

#[derive(Parser)]
pub(crate) struct TminOpts {
    pub program: PathBuf,
    pub grammar: String,
    pub input: PathBuf,
    #[clap(long, default_value = "100000")]
    iters: usize,
    #[clap(long)]
    output: Option<PathBuf>,
    #[clap(long)]
    snapshot: bool,
}

fn try_accept(
    sess: &mut JitFuzzingSession,
    stats: &mut Stats,
    engine: &dyn lod::ErasedEngine,
    oracle: &TminOracle,
    current: &mut Vec<u8>,
    current_entropy: &mut u32,
    candidate: &[u8],
    label: &str,
) -> bool {
    let candidate_entropy = engine.get_entropy(candidate);
    if candidate_entropy >= *current_entropy {
        return false;
    }
    if !oracle.accepts(sess, stats, candidate) {
        return false;
    }

    println!(
        "tmin: [{label}] smaller input {} -> {} bytes (entropy {} -> {}, {} edges)",
        current.len(),
        candidate.len(),
        *current_entropy,
        candidate_entropy,
        oracle.edge_count(),
    );
    *current = candidate.to_vec();
    *current_entropy = candidate_entropy;
    true
}

pub(crate) fn run(mod_spec: Arc<ModuleSpec>, opts: TminOpts) {
    let TminOpts {
        program: _,
        grammar,
        input: input_path,
        iters,
        output,
        snapshot,
    } = opts;

    let input = std::fs::read(&input_path).unwrap();
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(FeedbackOptions::minimal_code_coverage())
        .run_from_snapshot(snapshot)
        .instruction_limit(Some(2_000_000_000))
        .build();
    sess.initialize(&mut stats);

    let mut engine = lod_formats::make_engine(&grammar);
    engine.apply_config(&lod::EngineConfig {
        entropy_mode: lod::EntropyMode::LowEntropy,
        ..lod::EngineConfig::default()
    });
    engine.set_size_limit(sess.swarm.input_alloc_size());

    if !snapshot {
        // "Warm up" the session by running the initial input. This is a workaround for unstable targets / non-snapshot mode.
        let _ = sess.run_reusable(&input, true, &mut stats);
    }
    sess.reset_pass_coverage();
    let initial_res = sess.run_reusable(&input, true, &mut stats);
    let oracle = TminOracle::new(&sess, &initial_res);
    let initial_entropy = engine.get_entropy(&input);
    let initial_bytes = input.len();

    println!(
        "tmin: {:?} ({} bytes, entropy {}, {} edges, {})",
        input_path,
        initial_bytes,
        initial_entropy,
        oracle.edge_count(),
        if oracle.initial_crashed {
            "crashing"
        } else if oracle.initial_timeout {
            "timeout"
        } else {
            "non-crashing"
        }
    );
    engine.debug_levels(&input);

    let mut current = input;
    let mut current_entropy = initial_entropy;
    let mut rng = rand::rng();
    let mut lod_buf = Vec::new();
    let mut found_smaller = 0usize;

    // Lift the exact parse up the LOD chain and re-serialize: lossy-up tiers
    // re-emit *canonical* bytes, which is frequently already smaller / lower
    // entropy than the raw input (dropped padding, normalized length prefixes,
    // canonical CRCs). `feed(.., true)` climbs every tier at the root and in
    // nested sub-grammars; the `try_accept` oracle guarantees the canonical
    // form still reproduces the target edge coverage before we keep it.
    engine.set_input(&current);
    while dbg!(engine.try_convert_up()) {
        lod_buf.clear();
        engine.serialize_current(&mut lod_buf);
        try_accept(
            &mut sess,
            &mut stats,
            engine.as_ref(),
            &oracle,
            &mut current,
            &mut current_entropy,
            &lod_buf,
            "lift",
        );
    }

    // Structural minimization over the parsed tree: drop optional/repeated
    // fields, truncate lists (incl. `Vec<u8>` buffers), and reset fields to
    // their default. Unlike a byte-level sweep this survives compression /
    // checksums / length prefixes because the grammar re-serializes the edit.
    engine.set_input(&current);
    let mut shrink_pass_trials = 0;
    found_smaller += engine.shrink_pass(&mut |candidate, candidate_entropy| {
        shrink_pass_trials += 1;
        eprint!(
            "[shrink_pass] trying candidate {} ...\r",
            shrink_pass_trials
        );
        if !oracle.accepts(&mut sess, &mut stats, candidate) {
            return false;
        }
        println!(
            "tmin: [facet] smaller input {} -> {} bytes (entropy {} -> {}, {} edges)",
            current.len(),
            candidate.len(),
            current_entropy,
            candidate_entropy,
            oracle.edge_count(),
        );
        current.clear();
        current.extend_from_slice(candidate);
        current_entropy = candidate_entropy;
        true
    });
    eprintln!(
        "[shrink_pass] tried {} candidates, found {} smaller inputs",
        shrink_pass_trials, found_smaller
    );

    if found_smaller > 0 {
        engine.debug_levels(&current);
    }

    engine.reset_corpus();
    engine.feed(&current, true);

    'main: loop {
        for i in 0..iters {
            engine.set_input(&current);
            let seed = rng.next_u64();
            engine.mutate(&lod::MutationInputs { seed, cmplog: None });
            lod_buf.clear();
            engine.serialize_current(&mut lod_buf);
            lod_buf.truncate(sess.swarm.input_alloc_size());

            if try_accept(
                &mut sess,
                &mut stats,
                engine.as_ref(),
                &oracle,
                &mut current,
                &mut current_entropy,
                &lod_buf,
                &format!("lod [{i}/{iters}]"),
            ) {
                found_smaller += 1;
                engine.reset_corpus();
                engine.feed(&current, true);
                engine.debug_levels(&current);
                continue 'main;
            }
        }
        break 'main;
    }

    println!(
        "tmin: done — {} -> {} bytes (entropy {} -> {}), {found_smaller} smaller input(s) found",
        initial_bytes,
        current.len(),
        initial_entropy,
        current_entropy,
    );

    if let Some(out) = output {
        std::fs::write(&out, &current).unwrap();
        println!("tmin: wrote {:?}", out);
    } else if current_entropy < initial_entropy {
        let inphash = md5::compute(&current);
        let out = input_path.with_file_name(format!("{inphash:x}"));
        std::fs::write(&out, &current).unwrap();
        println!("tmin: wrote {:?}", out);
    }
}
