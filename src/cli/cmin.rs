use crate::HashSet;
use std::{cell::RefCell, path::PathBuf, sync::Arc};

use clap::Parser;

use crate::{
    ir::ModuleSpec,
    jit::{FeedbackOptions, JitFuzzingSession, Stats},
};

#[derive(Parser)]
pub(crate) struct CminOpts {
    pub program: String,
    #[clap(long)]
    corpus_dir: String,
    #[clap(long)]
    out_dir: Option<String>,
    #[clap(long, default_value = "10")]
    iters: usize,
    #[clap(long)]
    dry_run: bool,
    #[clap(long)]
    remove_unknown_files: bool,
    #[clap(long)]
    input_size_limit: Option<usize>,
}

pub(crate) fn run(mod_spec: Arc<ModuleSpec>, opts: CminOpts) {
    let CminOpts {
        program: _,
        corpus_dir,
        out_dir,
        iters,
        dry_run,
        remove_unknown_files,
        input_size_limit,
    } = opts;
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(FeedbackOptions {
            live_funcs: true,
            live_edges: true,
            // perffuzz_func: true,
            // perffuzz_edge: true,
            // perffuzz_edge_global: true,
            cmpcov_absdist: true,
            ..FeedbackOptions::nothing()
        })
        .build();
    sess.initialize(&mut stats);

    let corpus_dir = crate::fuzzer::FuzzOpts::resolve_corpus_dir(corpus_dir, &opts.program);

    let results = RefCell::new(Vec::<Vec<u8>>::new());

    let mut prev_files = Vec::new();
    for entry in std::fs::read_dir(&corpus_dir).expect("failed to list corpus dir") {
        let entry = entry.unwrap();
        let input = std::fs::read(entry.path()).unwrap();
        if input.len() > input_size_limit.unwrap_or(usize::MAX) {
            continue;
        }
        let res = sess.run_reusable(&input, false, &mut stats);
        res.expect_ok();
        if res.novel_coverage {
            results.borrow_mut().push(input.clone());
        }
        prev_files.push((entry.path(), input));
    }

    println!(
        "cmin: starting with {} (of {}) entries",
        results.borrow().len(),
        prev_files.len()
    );

    'main: loop {
        for i in 0..iters {
            sess.reset_pass_coverage();
            use rand::seq::SliceRandom;
            results.borrow_mut().shuffle(&mut rand::rng());
            let prev_len = results.borrow().len();
            results.borrow_mut().retain(|input| {
                let res = sess.run_reusable(input, false, &mut stats);
                res.novel_coverage
            });
            let new_len = results.borrow().len();
            let removed = prev_len - new_len;
            if removed > 0 {
                println!(
                    "cmin: down to {} entries ({:>3}) [{} iters left]",
                    new_len,
                    -(removed as isize),
                    iters - i
                );
                continue 'main;
            }
        }
        break;
    }

    let remaining_inputs = results.borrow_mut().iter().cloned().collect::<HashSet<_>>();
    if !dry_run {
        if let Some(path) = out_dir.as_ref() {
            println!(
                "cmin: saving {} inputs to {}...",
                results.borrow().len(),
                path
            );
            let path = PathBuf::from(path);
            for input in results.into_inner() {
                let mut inp_path = path.clone();
                let inphash = md5::compute(&input);
                inp_path.push(format!("{inphash:x}"));
                if !inp_path.is_file() {
                    let _ = std::fs::create_dir_all(&path);
                    let _ = std::fs::write(&inp_path, &input);
                    println!("saved {inp_path:?}");
                }
            }
        } else {
            println!(
                "cmin: retaining {} inputs in {:?}...",
                results.borrow().len(),
                corpus_dir
            );
            for (prev_path, input) in &prev_files {
                if remaining_inputs.contains(input) {
                    println!("[+] keeping  {:?}", &prev_path);
                    continue;
                }
                let filename = prev_path.file_name().unwrap().to_str().unwrap();
                let inphash = md5::compute(input);
                if filename == format!("{inphash:x}") || remove_unknown_files {
                    println!("[-] deleting {prev_path:?}");
                    let _ = std::fs::remove_file(prev_path);
                } else {
                    println!(
                        "would delete {prev_path:?} but file name is not based on md5 hash.. check your corpus dir!"
                    );
                }
            }
        }
    }
    println!("TL;DR: {} -> {}", prev_files.len(), remaining_inputs.len());
}
