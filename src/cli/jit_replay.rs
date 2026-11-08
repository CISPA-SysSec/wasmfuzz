//! `jit-replay`: replay a fixed corpus through the reusable and tracing stages
//! and print a feedback fingerprint plus timings, so JIT codegen changes can be
//! checked for identical feedback (compare the fingerprints of two binaries)
//! and timed (`--rounds`).

use std::{
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    time::Instant,
};

use crate::jit::{FeedbackOptions, JitFuzzingSession, Stats, TracingOptions};

fn fx<T: Hash>(v: &T) -> u64 {
    let mut h = rustc_hash::FxHasher::default();
    v.hash(&mut h);
    h.finish()
}

pub(crate) fn feedback_from_str(passes: &str) -> FeedbackOptions {
    match passes {
        "all" => FeedbackOptions::all_instrumentation(),
        // edges + funcs + bbs, cmpcov-hamming, edge-shortest-trace
        "warmup" => FeedbackOptions {
            cmpcov_hamming: true,
            edge_shortest_trace: true,
            ..FeedbackOptions::minimal_code_coverage()
        },
        list => {
            let mut opts = FeedbackOptions::nothing();
            for p in list.split(',').filter(|p| !p.is_empty()) {
                opts.activate_from_str(p);
            }
            opts
        }
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn run(
    program: &Path,
    corpus: &Path,
    passes: &str,
    rounds: usize,
    max_inputs: Option<usize>,
    instruction_limit: u64,
    cmplog: bool,
    json_out: Option<&PathBuf>,
) {
    let mut files: Vec<PathBuf> = std::fs::read_dir(corpus)
        .expect("failed to list corpus dir")
        .flat_map(|el| el.ok())
        .map(|el| el.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    if let Some(n) = max_inputs {
        files.truncate(n);
    }
    let inputs: Vec<Vec<u8>> = files
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .filter(|x| x.len() <= crate::TEST_CASE_SIZE_LIMIT)
        .collect();
    let input_bytes: usize = inputs.iter().map(Vec::len).sum();

    let mod_spec = super::parse_program(program);
    let feedback = feedback_from_str(passes);
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(feedback)
        .instruction_limit(Some(instruction_limit))
        .tracing(TracingOptions {
            cmplog,
            ..TracingOptions::default()
        })
        .build();
    let t = Instant::now();
    sess.initialize(&mut stats);
    let compile_reusable_s = t.elapsed().as_secs_f64();

    // Equivalence round: in-order replay, per-input trap + novelty.
    let mut per_input = rustc_hash::FxHasher::default();
    let mut novel_inputs = 0usize;
    let mut traps = 0usize;
    for inp in &inputs {
        let res = sess.run_reusable(inp, true, &mut stats);
        let trap = res.trap_kind.as_ref().map(|t| format!("{:?}", t.strip_location()));
        trap.hash(&mut per_input);
        res.novel_coverage_passes.hash(&mut per_input);
        novel_inputs += res.novel_coverage as usize;
        traps += trap.is_some() as usize;
    }
    let mut pass_fps = Vec::new();
    for pass in sess.passes.iter() {
        let (fp, count) = pass.saved_fingerprint();
        pass_fps.push((pass.shortcode(), fp, count));
    }
    let edges = sess.get_edge_cov();

    // Cmplog hooks hit, per input, order-independent within an input.
    let mut cmplog_fp = rustc_hash::FxHasher::default();
    let mut cmplog_entries = 0usize;
    let mut compile_tracing_s = 0.0;
    if cmplog {
        for (i, inp) in inputs.iter().enumerate() {
            let t = Instant::now();
            let res = sess.run_tracing_fresh(inp, &mut stats);
            if i == 0 {
                compile_tracing_s = t.elapsed().as_secs_f64();
            }
            let mut acc: u64 = 0;
            let mut n = 0usize;
            match res {
                Ok(ctx) => {
                    for (loc, set) in &ctx.cmplog {
                        for c in set {
                            acc = acc.wrapping_add(fx(&(loc, c)));
                            n += 1;
                        }
                    }
                }
                Err(trap) => format!("{:?}", trap.strip_location()).hash(&mut cmplog_fp),
            }
            acc.hash(&mut cmplog_fp);
            n.hash(&mut cmplog_fp);
            cmplog_entries += n;
        }
    }

    // Timing rounds: reusable stage only, coverage already saturated by the
    // equivalence round (as in a late campaign).
    let mut round_eps = Vec::new();
    for _ in 0..rounds {
        let t = Instant::now();
        for inp in &inputs {
            let _ = sess.run_reusable(inp, true, &mut stats);
        }
        round_eps.push(inputs.len() as f64 / t.elapsed().as_secs_f64());
    }

    let out = serde_json::json!({
        "program": program,
        "corpus": corpus,
        "passes": passes,
        "inputs": inputs.len(),
        "input_bytes": input_bytes,
        "instruction_limit": instruction_limit,
        "compile_reusable_s": compile_reusable_s,
        "compile_tracing_s": compile_tracing_s,
        "code_size": sess.reusable_stage.instance.as_ref().map(|i| i.code_size),
        "fingerprint": {
            "per_input": format!("{:016x}", per_input.finish()),
            "novel_inputs": novel_inputs,
            "traps": traps,
            "edges": edges,
            "passes": pass_fps.iter().map(|(s, fp, n)| serde_json::json!({
                "pass": s, "saved": format!("{fp:016x}"), "non_bottom": n,
            })).collect::<Vec<_>>(),
            "cmplog": format!("{:016x}", cmplog_fp.finish()),
            "cmplog_entries": cmplog_entries,
        },
        "execs_per_s": round_eps,
    });
    let text = serde_json::to_string_pretty(&out).unwrap();
    println!("{text}");
    if let Some(path) = json_out {
        std::fs::write(path, text).unwrap();
    }
}
