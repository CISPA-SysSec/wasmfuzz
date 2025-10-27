use clap::Parser;
use rand::Rng;
use std::{
    io::{BufRead, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use crate::{
    fuzzer::opts::{FlagBool, InstrumentationOpts},
    ir::ModuleSpec,
    jit::{FeedbackOptions, JitFuzzingSession, Stats, TracingOptions},
};

mod cmin;
#[cfg(feature = "concolic")]
mod concolic_explore;
#[cfg(feature = "reports")]
pub(crate) mod cov_html;
mod doctor;
#[cfg(feature = "reports")]
pub(crate) mod lcov;
mod misc_eval;
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
        program: PathBuf,
        #[clap(long)]
        dir: Option<String>,
        #[clap(long)]
        csv_out: String,
    },
    /// Run a single input.
    RunInput {
        program: PathBuf,
        inputs: Vec<String>,
        #[clap(long)]
        trace: bool,
        #[clap(long)]
        verbose_jit: bool,
        #[clap(long, default_value = "true")]
        print_stdout: FlagBool,
        #[clap(long, default_value = "false")]
        run_from_snapshot: FlagBool,
    },
    /// Check the system configuration and WebAssembly module for potential issues.
    Doctor {
        program: Option<String>,
    },
    /// Evaluate an input generator by assigning a score to desired coverage properties.
    #[clap(hide = true)]
    CoverageGym {
        program: PathBuf,
        generator: String,
        #[clap(long, default_value = "10000")]
        execs: usize,
        #[clap(long, default_value = "3")]
        simple_mutations_per_exec: usize,
        #[clap(long, default_value = "1000000")]
        instruction_limit: u64,
        #[clap(long)]
        cov_html: Option<PathBuf>,
        #[clap(long)]
        json_out: Option<PathBuf>,
    },
    /// Run a single specified input (repeatedly for timing).
    #[clap(hide = true)]
    BenchInput {
        program: PathBuf,
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
    /// Collect concolic traces for each input and try to flip branches for new coverage
    #[cfg(feature = "concolic")]
    ConcolicExplore {
        program: PathBuf,
        inputs: Vec<String>,
        #[clap(long)]
        dir: Option<String>,
    },
    /// Run various fuzzing configurations as an ensemble.
    Fuzz(crate::fuzzer::orc::CliOpts),
    /// Remove uninteresting inputs from corups.
    Cmin(cmin::CminOpts),
    /// Minimize crashing input.
    Tmin {
        program: PathBuf,
        input: PathBuf,
    },
    /// Watch directory for new entries and report total coverage over time.
    MonitorCov(monitor_cov::MonitorCovOpts),
    #[cfg(feature = "concolic_bitwuzla")]
    CheckConcolic {
        program: PathBuf,
        input: String,
    },
    ShowConcolic {
        program: PathBuf,
        input: String,
    },
    /// Collect line coverage from debug information.
    #[cfg(feature = "reports")]
    Lcov(lcov::LcovOpts),
    /// Create a line coverage report from the source code embedded in the module's debug info.
    #[cfg(feature = "reports")]
    CovHtml(cov_html::HtmlCovOpts),
    /// Run corpus on program and evaluate instrumentation pass relationship
    #[clap(hide = true)]
    EvalPassCorr {
        program: PathBuf,
        corpus: PathBuf,
        #[clap(long)]
        jsonl_out_path: PathBuf,
    },
    #[clap(hide = true)]
    EvalPassSpeed {
        program: PathBuf,
        corpus: PathBuf,
        #[clap(long)]
        jsonl_out_path: PathBuf,
    },
    #[clap(hide = true)]
    EvalPagesTouched {
        program: PathBuf,
        corpus: PathBuf,
        #[clap(long)]
        jsonl_out_path: PathBuf,
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
    #[clap(hide = true)]
    DumpEmbeddedSources {
        program: PathBuf,
        output: PathBuf,
        #[clap(long)]
        no_prefix: bool,
    },
    #[clap(hide = true)]
    #[cfg(feature = "reports")]
    CorpusBlame {
        program: PathBuf,
        corpus: PathBuf,
        file: Option<String>,
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
            run_from_snapshot,
        } => {
            let inputs = gather_inputs_paths(&None, &inputs, true);
            let mod_spec = parse_program(&program);
            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec)
                // .feedback(i.to_feedback_opts())
                .feedback(FeedbackOptions::nothing())
                .tracing(TracingOptions {
                    stdout: *print_stdout,
                    ..TracingOptions::default()
                })
                .debug(trace, verbose_jit)
                .instruction_limit(Some(2_000_000_000))
                .optimize_for_compilation_time(inputs.len() <= 10)
                .run_from_snapshot(*run_from_snapshot)
                .build();
            if inputs.is_empty() {
                println!("No input specified. Exiting.")
            }
            for input in inputs {
                println!("Testcase: {input:?}");
                let testcase = std::fs::read(input).expect("couldn't read input");
                assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
                let res = sess.run_tracing(&testcase, &mut stats).err().clone();

                if *print_stdout {
                    let stdout = &sess.tracing_context().stdout;
                    for line in stdout.lines() {
                        eprintln!("[STDOUT] {}", line.unwrap())
                    }
                }

                if let Some(trap_kind) = res {
                    if trap_kind.is_crash() {
                        println!(
                            "execution trapped with {trap_kind:?} which indicates that the target crashed"
                        );
                        break;
                    } else {
                        println!("execution stopped with {trap_kind:?} ");
                    }
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
            let mod_spec = parse_program(&program);
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
        #[cfg(feature = "concolic")]
        Subcommand::ConcolicExplore {
            program,
            inputs,
            dir,
        } => {
            let mod_spec = parse_program(&program);

            let concolic_provider = crate::concolic::ConcolicProvider::new(Some(mod_spec.clone()));
            let mut explorer =
                concolic_explore::ConcolicExplorer::new(mod_spec, &concolic_provider);
            let dir = dir.map(|dir| crate::fuzzer::FuzzOpts::resolve_corpus_dir(dir, &program));
            let input_paths = gather_inputs_paths(&dir, &inputs, true);
            if input_paths.is_empty() {
                for i in 5..10 {
                    let inp = vec![b'x'; 1 << i];
                    explorer.feed(inp);
                }
            }
            for path in input_paths {
                let input = std::fs::read(&path).unwrap();
                explorer.feed(input);
            }
            while explorer.has_work() {
                explorer.work();
            }
            dbg!(explorer.traces.len());
            dbg!(explorer.new_finds);
        }
        Subcommand::CorpusInfo {
            program,
            dir,
            csv_out,
        } => {
            let dir = dir.map(|dir| crate::fuzzer::FuzzOpts::resolve_corpus_dir(dir, &program));
            let input_paths = gather_inputs_paths(&dir, &[], true);
            let mod_spec = parse_program(&program);

            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec.clone())
                .feedback(FeedbackOptions {
                    live_edges: true,
                    ..FeedbackOptions::nothing()
                })
                .instruction_limit(Some(2_000_000_000))
                .build();
            sess.initialize(&mut stats);

            // TODO: track steps/fuel per input?
            // Note: It would be nice to have a "time-to-input" column here!
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
                if is_crash {
                    eprintln!("crash: {res:?} ({input_path:?})");
                }
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
            let mod_spec = parse_program(&opts.program);
            lcov::run(mod_spec, &input_paths, opts);
        }
        #[cfg(feature = "reports")]
        Subcommand::CovHtml(ref opts) => {
            let dir = opts.corpus.as_ref().map(|dir| {
                crate::fuzzer::FuzzOpts::resolve_corpus_dir(dir.to_owned(), &opts.program)
            });
            let input_paths = gather_inputs_paths(&dir, &opts.seed_files, true);
            let mod_spec = parse_program(&opts.program);
            cov_html::run(mod_spec, &input_paths, opts);
        }
        Subcommand::Fuzz(opts) => {
            let mod_spec = parse_program(&opts.g.program);
            crate::fuzzer::fuzz(mod_spec, opts);
        }
        Subcommand::Cmin(opts) => {
            let mod_spec = parse_program(&opts.program);
            cmin::run(mod_spec, opts);
        }
        Subcommand::Tmin { program, input } => {
            let mod_spec = parse_program(&PathBuf::from(&program));
            let input = std::fs::read(input).unwrap();

            {
                let mut stats = Stats::default();
                let mut sess = JitFuzzingSession::builder(mod_spec.clone())
                    .feedback(FeedbackOptions::nothing())
                    .build();
                sess.initialize(&mut stats);
                let res = sess.run(&input, &mut stats);
                assert!(res.is_crash());
            }

            let opts = crate::fuzzer::orc::CliOpts::parse_from(vec!["wasmfuzz-fuzz", "dummy.wasm"]);
            crate::fuzzer::fuzz(mod_spec, opts);

            todo!()
        }
        #[cfg(feature = "concolic_bitwuzla")]
        Subcommand::CheckConcolic { program, input } => {
            if cfg!(not(feature = "concolic_debug_verify")) {
                println!("[WARN] check-concolic without concolic_debug_verify feature");
            }

            let mod_spec = parse_program(&program);
            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec.clone())
                .feedback(FeedbackOptions::minimal_code_coverage())
                .tracing(TracingOptions {
                    concolic: true,
                    ..TracingOptions::default()
                })
                .build();
            sess.initialize(&mut stats);

            let input = std::fs::read(input).unwrap();
            assert!(input.len() <= crate::TEST_CASE_SIZE_LIMIT);
            sess.run_tracing_fresh(&input, &mut stats).unwrap();

            let context = sess
                .tracing_stage
                .instance
                .as_ref()
                .unwrap()
                .vmctx
                .concolic
                .clone();
            use crate::fuzzer::exhaustive::QueuedInputMutation;
            println!("running ConcolicOptimisticBitwuzla");
            let mut solver = crate::fuzzer::exhaustive::ConcolicOptimisticBitwuzla::new(
                &input,
                context.compact_to_trace(&input),
                mod_spec.clone(),
            );
            let mut _inp = input.clone();
            while solver.has_next() {
                solver.next(&mut _inp);
                if !solver.revert(&mut _inp) {
                    _inp.copy_from_slice(&input);
                }
            }

            println!("running ConcolicFlipPathsWithBitwuzla");
            let mut solver = crate::fuzzer::exhaustive::ConcolicFlipPathsWithBitwuzla::new(
                &input,
                context.compact_to_trace(&input),
                mod_spec,
            );
            let mut _inp = input.clone();
            while solver.has_next() {
                solver.next(&mut _inp);
                if !solver.revert(&mut _inp) {
                    _inp.copy_from_slice(&input);
                }
            }
        }
        Subcommand::ShowConcolic { program, input } => {
            let mod_spec = parse_program(&program);
            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec)
                .feedback(FeedbackOptions::nothing())
                .tracing(TracingOptions {
                    concolic: true,
                    ..TracingOptions::default()
                })
                .build();
            // sess.initialize(&mut stats);

            let input = std::fs::read(input).unwrap();
            assert!(input.len() <= crate::TEST_CASE_SIZE_LIMIT);
            sess.run_tracing_fresh(&input, &mut stats).unwrap();

            let context = sess
                .tracing_stage
                .instance
                .as_ref()
                .unwrap()
                .vmctx
                .concolic
                .clone();

            let trace = context.compact_to_trace(&input);
            for ev in &trace.events {
                trace.symvals.debug_event(ev);
            }
        }
        Subcommand::MonitorCov(opts) => monitor_cov::run(opts),
        Subcommand::EvalPassCorr {
            program,
            corpus,
            jsonl_out_path,
        } => {
            misc_eval::eval_pass_corr(&program, &corpus, &jsonl_out_path);
        }
        Subcommand::EvalPassSpeed {
            program,
            corpus,
            jsonl_out_path,
        } => {
            misc_eval::eval_pass_speed(&program, &corpus, &jsonl_out_path);
        }
        Subcommand::EvalPagesTouched {
            program,
            corpus,
            jsonl_out_path,
        } => {
            misc_eval::eval_pages_touched(&program, &corpus, &jsonl_out_path);
        }
        Subcommand::EvalSnapshotPerf {
            pages,
            touch,
            iters,
        } => {
            misc_eval::eval_snapshot_perf(pages, touch, iters);
        }
        Subcommand::Doctor { program } => doctor::run(program),

        Subcommand::CoverageGym {
            program,
            generator,
            execs,
            instruction_limit,
            cov_html,
            simple_mutations_per_exec,
            json_out,
        } => {
            use crate::instrumentation::{
                CodeCovInstrumentationPass, EdgeCoveragePass, EdgeShortestExecutionTracePass,
                FunctionCoveragePass, FunctionShortestExecutionTracePass,
            };
            use std::io::Read as _;
            let mod_spec = parse_program(&program);

            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec.clone())
                .feedback(FeedbackOptions {
                    live_funcs: true,
                    live_bbs: true,
                    live_edges: true,
                    func_shortest_trace: true,
                    edge_shortest_trace: true,
                    ..FeedbackOptions::nothing()
                })
                .instruction_limit(Some(instruction_limit))
                .build();
            sess.initialize(&mut stats);

            let mut child = std::process::Command::new(generator)
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let stdout = child.stdout.as_mut().unwrap();

            fn calculate_score(sess: &JitFuzzingSession) -> f32 {
                let funcs = sess.get_pass::<FunctionCoveragePass>().count_saved();
                let edges = sess.get_pass::<EdgeCoveragePass>().count_saved();
                let time_to_func = sess
                    .get_pass::<FunctionShortestExecutionTracePass>()
                    .coverage
                    .iter_saved()
                    .map(|(_func, &score)| 64. - (*score as f32 + 1.0).log2())
                    .sum::<f32>();
                let time_to_edge = sess
                    .get_pass::<EdgeShortestExecutionTracePass>()
                    .coverage
                    .iter_saved()
                    .map(|(_func, &score)| 64. - (*score as f32 + 1.0).log2())
                    .sum::<f32>();
                funcs as f32 * 10.0 + edges as f32 + time_to_func * 0.5 + time_to_edge * 0.1
            }

            let mut moving_score = 0.0;
            let mut stops = Vec::new();
            let mut buf = Vec::new();
            let mut rng = rand::rng();
            for i in 0..execs {
                let mut len = [0; 4];
                stdout.read_exact(&mut len).unwrap();
                let len = u32::from_le_bytes(len);
                buf.truncate(0);
                buf.resize(len as usize, 0);
                stdout.read_exact(&mut buf).unwrap();

                if len == 0 {
                    continue;
                }

                let mut restore_byte = None;
                for i in 0..simple_mutations_per_exec + 1 {
                    if let Some((pos, c)) = restore_byte.take() {
                        buf[pos] = c;
                    }
                    let res = sess.run_reusable(&buf, false, &mut stats);
                    res.expect_ok();
                    if res.novel_coverage {
                        res.print_cov_update(&sess, i);
                        // eprintln!("[{:05}] novel coverage {:?}", i, res.novel_coverage_passes);
                    }

                    if simple_mutations_per_exec > 0 {
                        let pos = rng.random_range(0..buf.len());
                        restore_byte = Some((pos, buf[pos]));
                        buf[pos] = rng.random();
                    }
                }

                if i.is_power_of_two() && i >= 512 {
                    let score = calculate_score(&sess);
                    if moving_score == 0.0 {
                        moving_score = score;
                    } else {
                        moving_score = moving_score * 0.5 + score * 0.5;
                    }
                    dbg!(score);
                    stops.push(score);
                    // dbg!(score);
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            moving_score = moving_score * 0.5 + calculate_score(&sess) * 0.5;
            dbg!(moving_score);
            println!("{moving_score}");

            if let Some(json_out_path) = json_out {
                let mut out_file = std::fs::File::create(json_out_path).unwrap();
                let log_obj = serde_json::json!({
                    "target": mod_spec.filename,
                    "score": moving_score,
                    "stops": stops,
                });
                let log_line = serde_json::to_string(&log_obj).unwrap();
                println!("{log_line}");
                out_file.write_all(log_line.as_bytes()).unwrap();
                out_file.write_all(b"\n").unwrap();
            }

            if let Some(out_path) = cov_html {
                #[cfg(feature = "reports")]
                crate::cli::cov_html::write_html_cov_report(mod_spec, &sess, &out_path);
                #[cfg(not(feature = "reports"))]
                panic!("trying to write html report without 'reports' feature")
            }
        }
        Subcommand::DumpEmbeddedSources {
            program,
            output,
            no_prefix,
        } => {
            let mod_spec = parse_program(&program);
            let object = symbolic_debuginfo::Object::parse(&mod_spec.wasm_binary)
                .expect("failed to parse file");
            assert!(object.has_debug_info());
            assert!(object.has_sources());
            let debug_session = object.debug_session().expect("failed to process file");

            let mut files = debug_session
                .files()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            // make sure we keep the copies that contain source code information
            files.sort_by_key(|f| (f.abs_path_str(), f.source_str().is_none()));
            files.dedup_by_key(|f| f.abs_path_str());

            let mut filtered = 0;
            let mut total = 0;
            let mut done = 0;
            for file in files {
                let Some(source) = file.source_str() else {
                    continue;
                };
                total += 1;
                let path = file.abs_path_str();
                let mut path = PathBuf::from(path);
                if !no_prefix {
                    let mut components = path.iter().collect::<Vec<_>>();
                    if components.len() < 4
                        || components[0] != "/"
                        || components[1] != "projects"
                        || components[3] != "repo"
                    {
                        filtered += 1;
                        continue;
                    }
                    // strip /projects/*/repo/
                    components.drain(1..4);
                    path = components.iter().collect();
                }
                let mut output_path = output.clone();
                output_path.push(path.strip_prefix("/").unwrap());
                std::fs::create_dir_all(output_path.parent().unwrap()).unwrap();
                std::fs::write(output_path, source.as_bytes()).unwrap();
                done += 1;
            }

            println!("Wrote {done} files to {output:?}.");
            if filtered > 0 {
                println!(
                    "Note: skipped {filtered} out of {total} files embedded in the debug info"
                );
            }
        }
        #[cfg(feature = "reports")]
        Subcommand::CorpusBlame {
            program,
            corpus,
            file: file_filter,
        } => {
            use crate::HashMap;
            let mod_spec = parse_program(&program);
            let mut corpus_entries = Vec::new();
            for entry in std::fs::read_dir(corpus).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let input = std::fs::read(&path).unwrap();
                corpus_entries.push((path, input));
            }
            // Prefer smaller inputs
            corpus_entries.sort_by_key(|(_, inp)| inp.len());

            let mut stats = Stats::default();
            let mut sess = JitFuzzingSession::builder(mod_spec.clone())
                .feedback(FeedbackOptions {
                    live_bbs: true,
                    ..FeedbackOptions::nothing()
                })
                .build();
            sess.initialize(&mut stats);
            struct Blame {
                map: HashMap<(usize, usize), usize>,
                inputs: Vec<String>,
                files: Vec<String>,
            }
            fn blame(report_info: &cov_html::ReportInfo, input: &str, blame: &mut Blame) {
                let inp_idx = blame.inputs.len();
                blame.inputs.push(input.to_string());
                for (file_idx, file) in report_info.files.iter().enumerate() {
                    for line_idx in file.line_coverage.covered.iter_ones() {
                        let key = (file_idx, line_idx);
                        if !blame.map.contains_key(&key) {
                            blame.map.insert(key, inp_idx);
                        }
                    }
                }
            }

            print!("blaming <init>\r");
            sess.run(b"YELLOW SUBMARINE", &mut stats).expect_ok();
            let mut report_info = cov_html::ReportInfo::new(mod_spec).unwrap();
            report_info.process_line_coverage(&sess);
            let mut res = Blame {
                map: HashMap::default(),
                inputs: Vec::new(),
                files: report_info.files.iter().map(|f| f.path.clone()).collect(),
            };
            blame(&report_info, "<init>", &mut res);

            for (path, input) in corpus_entries {
                print!("blaming {:?}: run                           \r", path);
                sess.run(&input, &mut stats).expect_ok();
                print!("blaming {:?}: process                       \r", path);
                report_info.process_line_coverage(&sess);
                print!("blaming {:?}: blame                         \r", path);
                blame(&report_info, &path.to_string_lossy(), &mut res);
            }

            for (file_idx, file) in res.files.iter().enumerate() {
                if let Some(file_filter) = &file_filter {
                    if !file.contains(file_filter) {
                        continue;
                    }
                }
                let mut blame_lines = res
                    .map
                    .iter()
                    .filter(|(k, _)| k.0 == file_idx)
                    .map(|((_, line), inp)| (line, inp))
                    .collect::<Vec<_>>();
                blame_lines.sort();
                for (line, inp) in blame_lines {
                    println!("[{}:{}] {}", file, line, res.inputs[*inp]);
                }
            }
        }
    }
}
