use std::sync::Arc;

use clap::Parser;

pub(crate) mod exhaustive;
pub(crate) mod i2s_patches;
pub mod opts;
pub(crate) mod orc;
mod worker;
mod worker_schedule;
pub(crate) use opts::FuzzOpts;
pub(crate) use worker::Worker;

use crate::fuzzer::orc::OrchestratorHandle;
pub(crate) use crate::fuzzer::worker::WorkerExit;
use crate::instrumentation::{CodeCovInstrumentationPass, EdgeCoveragePass};
use crate::ir::ModuleSpec;
use crate::jit::{FeedbackOptions, JitFuzzingSession, Stats};
use crate::simple_bus::MessageBus;

/// Picks the LOD grammar whose skeleton produces the most edge coverage on the
/// given module. Returns `None` when no grammar wins by a clear margin.
pub(crate) fn detect_lod_engine(mod_spec: Arc<ModuleSpec>) -> Option<Box<dyn lod::ErasedEngine>> {
    use std::cell::RefCell;

    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .optimize_for_compilation_time(true)
        .feedback(FeedbackOptions {
            live_edges: true,
            ..FeedbackOptions::nothing()
        })
        .build();
    sess.initialize(&mut stats);
    let cell = RefCell::new((sess, stats));
    lod::guess_engine(|bytes: &[u8]| -> f32 {
        let mut guard = cell.borrow_mut();
        let (sess, stats) = &mut *guard;
        sess.reset_pass_coverage();
        let _ = sess.run_reusable_fresh(bytes, true, stats);
        sess.get_pass::<EdgeCoveragePass>().count_saved() as f32
    })
}

pub(crate) fn fuzz(mod_spec: Arc<ModuleSpec>, opts: orc::CliOpts) {
    // https://stackoverflow.com/a/36031130
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    let cores = opts
        .cores
        .unwrap_or_else(|| std::thread::available_parallelism().unwrap().get());

    let start = std::time::Instant::now();
    if let Some(corpus_dir) = opts.g.corpus_dir() {
        let _ = std::fs::create_dir(corpus_dir);
    }

    let orc_handle = OrchestratorHandle::new(mod_spec.clone(), opts.clone());

    let mut seed_corpus = Vec::new();
    if let Some(path) = &opts.g.seed_dir() {
        let dir = std::fs::read_dir(path)
            .expect("failed to list seeds dir")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for entry in dir {
            let input =
                std::fs::read(entry.path()).expect("failed to read corpus entry (racy rm?)");
            if input.len() > opts.g.input_size_limit {
                println!(
                    "{:?}: Skipping due to size limit ({} > {})",
                    entry,
                    input.len(),
                    opts.g.input_size_limit
                );
                continue;
            }
            seed_corpus.push(input);
        }
    }
    if seed_corpus.is_empty() {
        seed_corpus.push(b"YELLOW SUBMARINE".to_vec());
    }
    orc_handle.load_corpus(seed_corpus);

    let lod_override: Option<String> = if matches!(opts.experiment, Some(orc::Experiment::Lod)) {
        let engine = detect_lod_engine(mod_spec.clone());
        let name = engine.as_ref().map(|e| e.format_name().to_string());
        eprintln!(
            "Lod experiment: guess_engine selected {:?} for {:?}",
            name, mod_spec.filename
        );
        assert!(
            name.is_some(),
            "guess_engine returned no winner for {:?}",
            mod_spec.filename
        );
        name
    } else {
        None
    };

    let mq = MessageBus::new();

    let mut handles = Vec::new();

    for core_idx in 0..cores {
        // TODO(perf): bind to core?

        let orc_handle = orc_handle.clone();
        let mod_spec = mod_spec.clone();
        let thread_name = format!("worker-{core_idx}");
        let mq = mq.clone();
        let opts = opts.clone();
        let lod_override = lod_override.clone();
        let handle = std::thread::Builder::new()
            .stack_size(32 << 20) // 32 MB instead of default 2 MB for large concolic eval stacks
            .name(thread_name)
            .spawn(move || {
                while orc_handle.should_continue() {
                    let mut fuzz_opts = FuzzOpts::parse_from(vec!["wasmfuzz-fuzz", "test.wasm"]);
                    fuzz_opts.x = opts.x.clone();
                    fuzz_opts.t.idle_timeout = Some("20s".parse().unwrap());
                    fuzz_opts.x.ignore_bus_inputs =
                        (!matches!(opts.experiment, Some(orc::Experiment::UseBusInputs))).into();
                    fuzz_opts.g.lod = opts.g.lod.clone();
                    if matches!(opts.experiment, Some(orc::Experiment::Lod)) {
                        assert!(fuzz_opts.g.lod.is_none());
                        fuzz_opts.g.lod = lod_override.clone();
                        assert!(
                            fuzz_opts.g.lod.is_some(),
                            "didn't find LOD module for {:?}",
                            mod_spec.filename
                        );
                    }
                    if matches!(opts.experiment, Some(orc::Experiment::Snapshot)) {
                        fuzz_opts.x.run_from_snapshot = true.into();
                    }

                    let mut worker = Worker::new(
                        mod_spec.clone(),
                        fuzz_opts.clone(),
                        mq.clone(),
                        core_idx,
                        Some(orc_handle.clone()),
                    );
                    let res = worker.run().unwrap();
                    use libafl::corpus::Corpus;
                    let res = if worker.solutions.count() != 0 {
                        WorkerExit::CrashFound
                    } else {
                        res
                    };
                    println!("Fuzz-task exited with {res:?}");

                    if worker.solutions.count() != 0 {
                        let mut inputs = Vec::new();
                        let id = worker.solutions.ids().next().unwrap();
                        let entry = worker.solutions.get(id).unwrap();
                        inputs.push(entry.borrow().input().as_ref().unwrap().as_ref().to_vec());
                        orc_handle.report_finds(inputs);
                    } else {
                        for _ in 0..10 {
                            if !dbg!(worker.inmemory_cmin(false)) {
                                break;
                            }
                        }

                        let mut inputs = Vec::new();
                        for i in worker.corpus.ids() {
                            let entry = worker.corpus.get(i).unwrap();
                            inputs.push(entry.borrow().input().as_ref().unwrap().as_ref().to_vec());
                        }
                        orc_handle.report_finds(inputs);
                    }
                }
            })
            .unwrap();
        handles.push(handle);
        std::thread::sleep(*opts.stagger_cores);
    }

    for handle in handles {
        handle.join().expect("Worker thread died");
    }

    orc_handle.shutdown();

    println!("This session ended after {:?}", start.elapsed());
}
