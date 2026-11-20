//! Hang triage helpers: per-input instruction counts (`fuel-census`) and a hot-spot profile of one
//! input (`hot-profile`).
//!
//! `fuel-census` replays inputs the way `monitor-cov` does (fresh instance per input), but with a
//! configurable instruction limit, and records how much fuel each input used. Inputs that trap
//! `OutOfFuel` at the limit are the hang candidates; the tail just below the limit is the
//! super-linear candidates.
//!
//! `hot-profile` runs one input with per-function and per-basic-block hit counters and prints the
//! hottest functions and blocks (resolved to source lines via DWARF when the module carries it).
//! Run it at a limit below the input's cost: the counters survive the `OutOfFuel` trap, so the
//! profile shows where the execution spends its budget.

use std::{
    io::Write,
    path::PathBuf,
    time::Instant,
};

use clap::Parser;

use crate::{
    instrumentation::{PerffuzzBBPass, PerffuzzFunctionPass},
    ir::{Location, ModuleSpec},
    jit::{FeedbackOptions, JitFuzzingSession, Stats, builtins::BULK_FUEL, module::TrapKind},
};

#[derive(Parser, Clone)]
pub(crate) struct FuelCensusOpts {
    pub(crate) program: PathBuf,
    /// Input files or directories (directories are listed one level deep).
    inputs: Vec<String>,
    #[clap(long, default_value = "20000000000")]
    instruction_limit: u64,
    #[clap(long)]
    memory_limit_pages: Option<u32>,
    /// Inputs larger than this are skipped (monitor-cov uses 65535).
    #[clap(long, default_value = "65535")]
    input_size_limit: usize,
    /// CSV output (default: stdout).
    #[clap(long)]
    csv_out: Option<PathBuf>,
}

fn trap_name(t: &Option<TrapKind>) -> &'static str {
    match t {
        None => "ok",
        Some(TrapKind::OutOfFuel(_)) => "oof",
        Some(TrapKind::OutOfMemory(_)) => "oom",
        Some(TrapKind::ExitTestcase(_)) => "exit",
        Some(TrapKind::SwarmShortCircuit(_)) => "short",
        Some(TrapKind::Abort(_)) => "crash",
    }
}

fn fuel_used(sess: &JitFuzzingSession) -> u64 {
    let inst = sess.reusable_stage.instance.as_ref().unwrap();
    inst.vmctx.fuel_init.saturating_sub(inst.vmctx.fuel)
}

pub(crate) fn fuel_census(mod_spec: std::sync::Arc<ModuleSpec>, opts: FuelCensusOpts) {
    let paths = super::gather_inputs_paths(&None, &opts.inputs, true);
    let mut sess = JitFuzzingSession::builder(mod_spec.clone())
        .feedback(FeedbackOptions::nothing())
        .instruction_limit(Some(opts.instruction_limit))
        .memory_limit_pages(opts.memory_limit_pages)
        .build();
    let mut out: Box<dyn Write> = match &opts.csv_out {
        Some(p) => Box::new(std::io::BufWriter::new(std::fs::File::create(p).unwrap())),
        None => Box::new(std::io::stdout()),
    };
    writeln!(out, "input,size,fuel,result,exec_us,heap_pages,bulk_fuel").unwrap();
    let mut stats = Stats::default();
    for path in paths {
        let Ok(input) = std::fs::read(&path) else {
            continue;
        };
        if input.len() > opts.input_size_limit {
            continue;
        }
        let start = Instant::now();
        let bulk0 = BULK_FUEL.get();
        let res = sess.run_reusable_fresh(&input, false, &mut stats);
        let bulk = BULK_FUEL.get() - bulk0;
        let us = start.elapsed().as_micros();
        let fuel = fuel_used(&sess);
        let pages = sess.reusable_stage.instance.as_ref().unwrap().vmctx.heap_pages;
        writeln!(
            out,
            "{},{},{},{},{},{},{}",
            path.display(),
            input.len(),
            fuel,
            trap_name(&res.trap_kind),
            us,
            pages,
            bulk
        )
        .unwrap();
        out.flush().unwrap();
    }
}

#[derive(Parser, Clone)]
pub(crate) struct HotProfileOpts {
    pub(crate) program: PathBuf,
    /// Input files or directories.
    inputs: Vec<String>,
    #[clap(long, default_value = "2000000000")]
    instruction_limit: u64,
    #[clap(long, default_value = "15")]
    top: usize,
    /// One TSV line per input (input, result, fuel, hottest block, its source, hottest
    /// function by calls) instead of the full report.
    #[clap(long)]
    tsv: bool,
}

/// Innermost (inlined) function name and file:line for a wasm code offset.
fn resolve(funcs: &[symbolic::debuginfo::Function<'_>], addr: u64) -> Option<String> {
    fn walk(f: &symbolic::debuginfo::Function<'_>, addr: u64) -> Option<String> {
        if f.address > addr || f.address + f.size <= addr {
            return None;
        }
        for il in &f.inlinees {
            if let Some(s) = walk(il, addr) {
                return Some(s);
            }
        }
        let mut best = None;
        for line in &f.lines {
            if line.address > addr {
                break;
            }
            if line.line != 0 {
                best = Some(format!("{}:{}", line.file.path_str(), line.line));
            }
        }
        Some(format!(
            "{} @ {}",
            f.name.as_str(),
            best.unwrap_or_default()
        ))
    }
    funcs.iter().find_map(|f| walk(f, addr))
}

pub(crate) fn hot_profile(mod_spec: std::sync::Arc<ModuleSpec>, opts: HotProfileOpts) {
    let paths = super::gather_inputs_paths(&None, &opts.inputs, true);
    let mut sess = JitFuzzingSession::builder(mod_spec.clone())
        .feedback(FeedbackOptions {
            perffuzz_func: true,
            perffuzz_bb: true,
            ..FeedbackOptions::nothing()
        })
        .instruction_limit(Some(opts.instruction_limit))
        .build();
    let view = symbolic::common::ByteView::from_slice(&mod_spec.wasm_binary);
    let object = symbolic::debuginfo::Object::parse(&view).ok();
    let dbg = object.as_ref().and_then(|o| o.debug_session().ok());
    let funcs: Vec<_> = dbg
        .as_ref()
        .map(|s| s.functions().filter_map(|f| f.ok()).collect())
        .unwrap_or_default();
    let bb_src = |loc: &Location| -> String {
        let func = &mod_spec.functions[loc.function as usize];
        for (i, &off_rel) in func.operator_offset_rel.iter().enumerate() {
            if func.operator_basic_block[i].0 == loc.index {
                let addr = (func.operators_wasm_bin_offset_base + off_rel as usize) as u64;
                return resolve(&funcs, addr).unwrap_or_default();
            }
        }
        String::new()
    };
    let mut stats = Stats::default();
    for path in paths {
        let Ok(input) = std::fs::read(&path) else {
            continue;
        };
        sess.reset_pass_coverage();
        let res = sess.run_reusable_fresh(&input, false, &mut stats);
        let fuel = fuel_used(&sess);
        let mut fns: Vec<(u32, u32)> = sess
            .get_pass::<PerffuzzFunctionPass>()
            .coverage
            .iter_saved()
            .map(|(k, v)| (k.0, **v))
            .filter(|&(_, v)| v > 0)
            .collect();
        fns.sort_by_key(|&(_, v)| std::cmp::Reverse(v));
        let mut bbs: Vec<(Location, u32)> = sess
            .get_pass::<PerffuzzBBPass>()
            .coverage
            .iter_saved()
            .map(|(k, v)| (*k, **v))
            .filter(|&(_, v)| v > 0)
            .collect();
        bbs.sort_by_key(|&(_, v)| std::cmp::Reverse(v));
        if opts.tsv {
            let (bb, bbv) = bbs.first().copied().unwrap_or((Location { function: 0, index: 0 }, 0));
            let (f, fv) = fns.first().copied().unwrap_or((0, 0));
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                path.display(),
                trap_name(&res.trap_kind),
                fuel,
                mod_spec.format_location(bb),
                bbv,
                bb_src(&bb),
                mod_spec.functions[f as usize].symbol,
                fv
            );
            continue;
        }
        println!(
            "== {} result={} fuel={} limit={}",
            path.display(),
            trap_name(&res.trap_kind),
            fuel,
            opts.instruction_limit
        );
        println!("== hottest functions (calls)");
        for (f, v) in fns.iter().take(opts.top) {
            println!("{v:>12} {}", mod_spec.functions[*f as usize].symbol);
        }
        println!("== hottest basic blocks (hits)");
        for (loc, v) in bbs.iter().take(opts.top) {
            println!("{v:>12} {} | {}", mod_spec.format_location(*loc), bb_src(loc));
        }
    }
}

#[derive(Parser, Clone)]
pub(crate) struct HangTminOpts {
    pub(crate) program: PathBuf,
    input: PathBuf,
    #[clap(long)]
    output: PathBuf,
    /// The input must still run out of fuel at this limit.
    #[clap(long, default_value = "2000000000")]
    instruction_limit: u64,
    /// Accept any out-of-fuel candidate, not only ones whose hottest basic block (the loop) is
    /// the original one.
    #[clap(long)]
    any_hang: bool,
}

/// Delta-debugging minimiser for hangs: keeps a candidate when it still traps `OutOfFuel` and its
/// hottest basic block is unchanged (so the reduction does not slide into a different loop).
pub(crate) fn hang_tmin(mod_spec: std::sync::Arc<ModuleSpec>, opts: HangTminOpts) {
    let mut cur = std::fs::read(&opts.input).unwrap();
    let mut sess = JitFuzzingSession::builder(mod_spec.clone())
        .feedback(FeedbackOptions {
            perffuzz_bb: true,
            ..FeedbackOptions::nothing()
        })
        .instruction_limit(Some(opts.instruction_limit))
        .build();
    let mut stats = Stats::default();
    let mut probe = |sess: &mut JitFuzzingSession, inp: &[u8]| -> Option<Location> {
        sess.reset_pass_coverage();
        let res = sess.run_reusable_fresh(inp, false, &mut stats);
        if !matches!(res.trap_kind, Some(TrapKind::OutOfFuel(_))) {
            return None;
        }
        sess.get_pass::<PerffuzzBBPass>()
            .coverage
            .iter_saved()
            .max_by_key(|(_, v)| ***v)
            .map(|(k, _)| *k)
    };
    let Some(sig) = probe(&mut sess, &cur) else {
        println!("hang-tmin: input does not run out of fuel at {}", opts.instruction_limit);
        std::process::exit(1);
    };
    println!(
        "hang-tmin: {} bytes, hottest block {}",
        cur.len(),
        mod_spec.format_location(sig)
    );
    let mut tests = 0usize;
    let mut accept = |sess: &mut JitFuzzingSession, cand: &[u8]| -> bool {
        tests += 1;
        match probe(sess, cand) {
            Some(s) => opts.any_hang || s == sig,
            None => false,
        }
    };
    // ddmin-style chunk removal, then byte-wise zeroing of what is left
    let mut chunk = cur.len().next_power_of_two() / 2;
    while chunk >= 1 {
        let mut i = 0;
        let mut progress = false;
        while i < cur.len() {
            let end = (i + chunk).min(cur.len());
            let mut cand = cur[..i].to_vec();
            cand.extend_from_slice(&cur[end..]);
            if !cand.is_empty() && accept(&mut sess, &cand) {
                cur = cand;
                progress = true;
            } else {
                i += chunk;
            }
        }
        if !progress {
            chunk /= 2;
        }
    }
    for i in 0..cur.len() {
        for b in [0u8, b'0'] {
            if cur[i] == b {
                break;
            }
            let mut cand = cur.clone();
            cand[i] = b;
            if accept(&mut sess, &cand) {
                cur = cand;
                break;
            }
        }
    }
    std::fs::write(&opts.output, &cur).unwrap();
    println!("hang-tmin: {} bytes after {tests} tests -> {}", cur.len(), opts.output.display());
}
