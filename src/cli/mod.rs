use clap::Parser;
use std::{
    fs::File,
    io::{BufRead, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use crate::{
    fuzzer::opts::{FlagBool, InstrumentationOpts},
    ir::ModuleSpec,
    jit::{FeedbackOptions, JitFuzzingSession, PassesGen, Stats, TracingOptions},
};

mod cmin;
#[cfg(feature = "reports")]
pub(crate) mod cov_html;
#[cfg(feature = "reports")]
pub(crate) mod lcov;
mod monitor_cov;

#[derive(Parser)]
pub(crate) struct Opts {
    // /// A level of verbosity, and can be used multiple times
    // #[clap(short, long, parse(from_occurrences))]
    // verbose: i32,
    #[clap(subcommand)]
    subcmd: Subcommand,
}

#[derive(Parser)]
pub(crate) enum Subcommand {
    #[clap(hide = true)]
    CorpusInfo {
        program: String,
        #[clap(long)]
        dir: Option<String>,
        #[clap(long)]
        csv_out: String,
    },
    /// Run a single input.
    RunInput {
        program: String,
        inputs: Vec<String>,
        #[clap(long)]
        trace: bool,
        #[clap(long)]
        verbose_jit: bool,
        #[clap(long, default_value = "true")]
        print_stdout: FlagBool,
    },
    /// Run a single specified input (repeatedly for timing).
    #[clap(hide = true)]
    BenchInput {
        program: String,
        inputs: Vec<String>,
        #[clap(long)]
        trace: bool,
        #[clap(long)]
        verbose: bool,
        #[clap(long, default_value = "true")]
        run_from_snapshot: FlagBool,
        #[clap(long, default_value = "1000000")]
        execs: u32,
        #[clap(flatten)]
        i: InstrumentationOpts,
    },
    /// Run various fuzzing configurations as an ensemble.
    Fuzz(crate::fuzzer::orc::CliOpts),
    /// Remove uninteresting inputs from corups.
    Cmin(cmin::CminOpts),
    /// Watch directory for new entries and report total coverage over time.
    MonitorCov(monitor_cov::MonitorCovOpts),
    /// Collect line coverage from debug information.
    #[cfg(feature = "reports")]
    Lcov(lcov::LcovOpts),
    /// Create a line coverage report from the source code embedded in the module's debug info.
    #[cfg(feature = "reports")]
    CovHtml(cov_html::HtmlCovOpts),
    /// Run corpus on program and evaluate instrumentation pass relationship
    #[clap(hide = true)]
    EvalPassCorr {
        program: String,
        corpus: String,
        #[clap(long)]
        jsonl_out_path: String,
    },
    #[clap(hide = true)]
    EvalPassSpeed {
        program: String,
        corpus: String,
        #[clap(long)]
        jsonl_out_path: String,
    },
    #[clap(hide = true)]
    EvalPagesTouched {
        program: String,
        corpus: String,
        #[clap(long)]
        jsonl_out_path: String,
    },
    #[clap(hide = true)]
    EvalSnapshotPerf {
        #[clap(long, default_value = "420")]
        pages: usize,
        #[clap(long, default_value = "69")]
        touch: usize,
        #[clap(long, default_value = "10000")]
        iters: usize,
    },
}

fn parse_program(path: &Path) -> Arc<ModuleSpec> {
    // Note: `wat::parse_file` also handles .wasm files
    #[cfg(feature = "compressed_harnesses")]
    let module_binary = if path.extension() == Some(std::ffi::OsStr::new("zst")) {
        let data = std::fs::read(path).unwrap();
        zstd::decode_all(data.as_slice()).unwrap()
    } else {
        wat::parse_file(path).unwrap()
    };
    #[cfg(not(feature = "compressed_harnesses"))]
    let module_binary = wat::parse_file(path).unwrap();

    use wasmparser::WasmFeatures;
    let features = WasmFeatures::SATURATING_FLOAT_TO_INT
        | WasmFeatures::SIGN_EXTENSION
        | WasmFeatures::MULTI_VALUE
        | WasmFeatures::BULK_MEMORY
        | WasmFeatures::FLOATS
        | WasmFeatures::MUTABLE_GLOBAL
        | WasmFeatures::REFERENCE_TYPES;
    wasmparser::Validator::new_with_features(features)
        .validate_all(&module_binary)
        .expect("wasm file is using unsupported feature proposals");

    Arc::new(
        ModuleSpec::parse(path.file_name().unwrap().to_str().unwrap(), &module_binary).unwrap(),
    )
}

fn gather_inputs_paths(dir: &Option<PathBuf>, inputs_paths: &[String], sort: bool) -> Vec<PathBuf> {
    let mut paths: Vec<_> = inputs_paths.iter().map(PathBuf::from).collect();
    if let Some(dir) = dir {
        paths.insert(0, dir.clone());
    }
    let mut inputs_paths = Vec::new();
    for path in paths {
        if path.is_dir() {
            for entry in std::fs::read_dir(path).expect("failed to list corpus dir") {
                let entry = entry.unwrap();
                inputs_paths.push(entry.path());
            }
        } else {
            inputs_paths.push(path);
        }
    }
    if sort {
        inputs_paths.sort();
    }
    inputs_paths
}

pub(crate) fn main() {
    let opts: Opts = Opts::parse();

    match opts.subcmd {
        Subcommand::RunInput {
            program,
            inputs,
            trace,
            verbose_jit,
            print_stdout,
        } => {
            let inputs = gather_inputs_paths(&None, &inputs, true);
            let mod_spec = parse_program(&PathBuf::from(program));
            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec)
                // .feedback(i.to_feedback_opts())
                .feedback(FeedbackOptions::nothing())
                .tracing(TracingOptions {
                    stdout: *print_stdout,
                    ..TracingOptions::default()
                })
                .debug(trace, verbose_jit)
                .build();
            sess.initialize(&mut stats);

            if inputs.is_empty() {
                println!("No input specified. Exiting.")
            }
            for input in inputs {
                println!("Testcase: {input:?}");
                let testcase = std::fs::read(input).expect("couldn't read input");
                assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
                let res = sess.run_tracing_fresh(&testcase, &mut stats).err().clone();

                if *print_stdout {
                    let stdout = &sess.tracing_context().stdout;
                    for line in stdout.lines() {
                        eprintln!("[STDOUT] {}", line.unwrap())
                    }
                }

                if let Some(trap_kind) = res {
                    println!(
                        "execution trapped with {:?} which indicates that the target crashed",
                        trap_kind
                    );
                    break;
                }
            }
        }
        Subcommand::BenchInput {
            program,
            inputs,
            trace,
            verbose,
            execs,
            i,
            run_from_snapshot,
        } => {
            let inputs = gather_inputs_paths(&None, &inputs, true);
            let mod_spec = parse_program(&PathBuf::from(program));
            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec)
                .feedback(i.to_feedback_opts())
                .feedback(FeedbackOptions::nothing())
                .tracing(TracingOptions {
                    stdout: true,
                    ..TracingOptions::default()
                })
                .debug(trace, verbose)
                .run_from_snapshot(*run_from_snapshot)
                .build();
            sess.initialize(&mut stats);

            for inp in &inputs {
                println!("Testcase: {inp:?}");
                let testcase = std::fs::read(inp).expect("couldn't read seed");
                assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
                sess.run(&testcase, &mut stats).expect_ok();
            }

            if !inputs.is_empty() {
                println!("Bench: {:?} ({})", inputs[0], execs);
                let start = Instant::now();
                let testcase = std::fs::read(&inputs[0]).expect("couldn't read seed");
                for i in 0u32..execs {
                    sess.run(&testcase, &mut stats).expect_ok();
                    if i.is_power_of_two() {
                        println!("{} {}", i, i.trailing_zeros());
                    }
                }
                let elapsed = start.elapsed();
                println!(
                    "done after {:?} ({:.02} exec/s)",
                    elapsed,
                    execs as f32 / elapsed.as_secs_f32()
                )
            }
        }
        Subcommand::CorpusInfo {
            program,
            dir,
            csv_out,
        } => {
            let dir = dir.map(|dir| crate::fuzzer::FuzzOpts::resolve_corpus_dir(dir, &program));
            let input_paths = gather_inputs_paths(&dir, &[], true);
            let mod_spec = parse_program(&PathBuf::from(program));

            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec.clone())
                .feedback(FeedbackOptions {
                    live_edges: true,
                    ..FeedbackOptions::nothing()
                })
                .build();
            sess.initialize(&mut stats);

            // TODO: track steps/fuel per input?
            let mut csv_out = std::fs::File::create(csv_out).unwrap();
            writeln!(
                csv_out,
                "module,input,size,crashed,exec_us,edge_cov,total_edge_cov"
            )
            .unwrap();
            for input_path in &input_paths {
                let input = std::fs::read(input_path).unwrap();
                sess.reset_pass_coverage();
                let start = std::time::Instant::now();
                let res = sess.run(&input, &mut stats);
                let exec_us = start.elapsed().as_micros();
                let is_crash = res.is_crash();
                let edge_cov = sess.get_edge_cov().unwrap();
                writeln!(
                    csv_out,
                    "{},{},{},{},{},{},",
                    mod_spec.filename,
                    input_path.file_stem().unwrap().to_string_lossy(),
                    input.len(),
                    is_crash as u8,
                    exec_us,
                    edge_cov
                )
                .unwrap();
            }

            sess.reset_pass_coverage();
            let start = std::time::Instant::now();
            for input_path in &input_paths {
                let input = std::fs::read(input_path).unwrap();
                let _ = sess.run(&input, &mut stats);
            }
            let exec_us = start.elapsed().as_micros();
            let total_edge_cov = sess.get_edge_cov().unwrap();
            writeln!(
                csv_out,
                "{},,,,{},,{}",
                mod_spec.filename, exec_us, total_edge_cov
            )
            .unwrap();
        }
        #[cfg(feature = "reports")]
        Subcommand::Lcov(ref opts) => {
            let dir = opts.dir.as_ref().map(|dir| {
                crate::fuzzer::FuzzOpts::resolve_corpus_dir(dir.to_owned(), &opts.program)
            });
            let input_paths = gather_inputs_paths(&dir, &opts.seed_files, true);
            let mod_spec = parse_program(&PathBuf::from(&opts.program));
            lcov::run(mod_spec, &input_paths, opts);
        }
        #[cfg(feature = "reports")]
        Subcommand::CovHtml(ref opts) => {
            let dir = opts.corpus.as_ref().map(|dir| {
                crate::fuzzer::FuzzOpts::resolve_corpus_dir(dir.to_owned(), &opts.program)
            });
            let input_paths = gather_inputs_paths(&dir, &opts.seed_files, true);
            let mod_spec = parse_program(&PathBuf::from(&opts.program));
            cov_html::run(mod_spec, &input_paths, opts);
        }
        Subcommand::Fuzz(opts) => {
            let mod_spec = parse_program(&PathBuf::from(&opts.g.program));
            crate::fuzzer::fuzz(mod_spec, opts);
        }
        Subcommand::Cmin(opts) => {
            let mod_spec = parse_program(&PathBuf::from(&opts.program));
            cmin::run(mod_spec, opts);
        }

        Subcommand::MonitorCov(opts) => monitor_cov::run(opts),

        Subcommand::EvalPassCorr {
            program,
            corpus,
            jsonl_out_path,
        } => {
            let mut out_file = File::create(jsonl_out_path).unwrap();
            let mod_spec = parse_program(&PathBuf::from(program));
            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec)
                .feedback(FeedbackOptions::all_instrumentation())
                .build();
            sess.initialize(&mut stats);

            let mut files = std::fs::read_dir(corpus)
                .expect("failed to list corpus dir")
                .flat_map(|el| el.ok())
                .collect::<Vec<_>>();
            files.sort_by_cached_key(|entry| entry.metadata().unwrap().created().unwrap());

            for entry in files {
                let inp = entry.path();
                println!("{:?}", inp);
                let testcase = std::fs::read(inp).expect("couldn't read seed");
                assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
                // let before = sess.covdb.features().to_map();
                let res = sess.run_reusable_fresh(&testcase, false, &mut stats);
                res.expect_ok();
                let changed = res.novel_coverage_passes;

                // let check_dom = |a, b| {
                //     if changed.contains(b) {
                //         assert!(changed.contains(a), "unexpected sensitivity break");
                //     };
                // };
                // check_dom("covered_edges", "covered_basic_blocks");
                // check_dom("covered_basic_blocks", "covered_functions");

                let log_line = serde_json::to_string(&changed).unwrap();
                println!("{}", log_line);
                out_file.write_all(log_line.as_bytes()).unwrap();
                out_file.write_all(b"\n").unwrap();
            }
        }

        Subcommand::EvalPassSpeed {
            program,
            corpus,
            jsonl_out_path,
        } => {
            let mut out_file = File::create(jsonl_out_path).unwrap();
            let mod_spec = parse_program(&PathBuf::from(program));
            let mut stats = Stats::default();

            let passes = {
                let feedback = FeedbackOptions::all_instrumentation();
                let gen = crate::jit::FullFeedbackPasses {
                    opts: feedback,
                    spec: mod_spec.clone(),
                };
                gen.generate_passes()
            };

            let mut configs = passes
                .0
                .into_iter()
                .map(|pass| {
                    (
                        pass.shortcode(),
                        Box::new(crate::jit::SinglePassGen::new(pass)) as Box<dyn PassesGen>,
                    )
                })
                .collect::<Vec<_>>();
            configs.insert(0, ("<nothing>", Box::new(crate::jit::EmptyPassesGen)));

            for (key, generator) in configs {
                dbg!(key);
                let mut sess = JitFuzzingSession::builder(mod_spec.clone())
                    .passes_generator(generator.into())
                    .build();
                let reusable_jit_start = Instant::now();
                sess.initialize(&mut stats);
                let reusable_jit_time = reusable_jit_start.elapsed();

                let mut files = std::fs::read_dir(&corpus)
                    .expect("failed to list corpus dir")
                    .flat_map(|el| el.ok())
                    .collect::<Vec<_>>();
                files.sort_by_cached_key(|entry| entry.metadata().unwrap().created().unwrap());

                // dummy input for trapping jit timing
                sess.run_reusable(&[0], false, &mut stats).expect_ok();

                let reusable_run_start = Instant::now();
                for entry in &files {
                    let inp = entry.path();
                    let testcase = std::fs::read(inp).expect("couldn't read seed");
                    assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
                    sess.run_reusable(&testcase, false, &mut stats).expect_ok();
                }
                let reusable_run_time = reusable_run_start.elapsed();

                let log_obj = serde_json::json!({
                    "pass": key,
                    "reusable_run_seconds": reusable_run_time.as_secs_f32(),
                    "reusable_jit_seconds": reusable_jit_time.as_secs_f32(),
                    "reusable_jit_code_bytes": sess.reusable_stage.instance.as_ref().unwrap().code_size,
                });
                let log_line = serde_json::to_string(&log_obj).unwrap();
                println!("{}", log_line);
                out_file.write_all(log_line.as_bytes()).unwrap();
                out_file.write_all(b"\n").unwrap();
            }
        }
        Subcommand::EvalPagesTouched {
            program,
            corpus,
            jsonl_out_path,
        } => {
            let mut out_file = File::options()
                .create(true)
                .append(true)
                .open(jsonl_out_path)
                .unwrap();

            let mod_spec = parse_program(&PathBuf::from(program));

            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec.clone()).build();
            sess.initialize(&mut stats);

            let mut files = std::fs::read_dir(corpus)
                .expect("failed to list corpus dir")
                .flat_map(|el| el.ok())
                .collect::<Vec<_>>();
            files.sort_by_cached_key(|entry| entry.metadata().unwrap().created().unwrap());

            for entry in &files {
                let inp = entry.path();
                let testcase = std::fs::read(&inp).expect("couldn't read seed");
                assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
                sess.run_reusable_fresh(&testcase, false, &mut stats)
                    .expect_ok();
                let reusable_instance = sess.reusable_stage.instance.as_mut().unwrap();
                let modified_4k = reusable_instance
                    .vmctx
                    .heap_alloc
                    .count_modified_pages(1 << 12);
                let modified_64k = reusable_instance
                    .vmctx
                    .heap_alloc
                    .count_modified_pages(1 << 16);
                let pages_64k = reusable_instance.vmctx.heap_pages;
                let pages_4k = pages_64k * (1 << (16 - 12));

                let test_case = inp.file_name().unwrap().to_string_lossy();
                let log_obj = serde_json::json!({
                    "target": mod_spec.filename,
                    "test_case": test_case,
                    "modified_4k": modified_4k,
                    "modified_64k": modified_64k,
                    "pages_64k": pages_64k,
                    "pages_4k": pages_4k,
                });
                let log_line = serde_json::to_string(&log_obj).unwrap();
                println!("{}", log_line);
                out_file.write_all(log_line.as_bytes()).unwrap();
                out_file.write_all(b"\n").unwrap();
            }
        }
        Subcommand::EvalSnapshotPerf {
            pages,
            touch,
            iters,
        } => {
            assert!(RestoreDirtyLKMMapping::is_available());
            use crate::cow_memory::*;
            use rand::seq::SliceRandom;
            #[derive(Debug)]
            enum Provider {
                Dummy,
                CoW,
                Criu,
                Lkm,
            }
            let accessible_size = pages << 12;
            let mapping_size = accessible_size;
            let mut page_offsets = (0..pages).map(|x| x << 12).collect::<Vec<_>>();
            let mut rng = rand::thread_rng();

            for provider in &[
                Provider::Dummy,
                Provider::CoW,
                Provider::Criu,
                Provider::Lkm,
            ] {
                dbg!(provider);
                let mut mapping: Box<dyn ResettableMapping> = match provider {
                    Provider::Dummy => Box::new(DummyMapping::new(accessible_size, mapping_size)),
                    Provider::CoW => Box::new(CowResetMapping::new(accessible_size, mapping_size)),
                    Provider::Criu => Box::new(CriuMapping::new(accessible_size, mapping_size)),
                    Provider::Lkm => {
                        Box::new(RestoreDirtyLKMMapping::new(accessible_size, mapping_size))
                    }
                };

                mapping.restore();
                dbg!(provider);

                let mut chksum = 0;
                let start = Instant::now();
                for _ in 0..iters {
                    let slice = mapping.as_mut_slice();
                    page_offsets.shuffle(&mut rng);
                    page_offsets
                        .iter()
                        .take(touch)
                        .for_each(|&i| slice[i] = 0x42);
                    mapping.restore();
                    let slice = mapping.as_slice();
                    chksum += page_offsets
                        .iter()
                        .take(touch)
                        .map(|&i| slice[i] as usize)
                        .sum::<usize>();
                }
                println!(
                    "{:?}: {:?} (chksum: {:#x})",
                    provider,
                    start.elapsed(),
                    chksum
                )
            }
        }
    }
}
