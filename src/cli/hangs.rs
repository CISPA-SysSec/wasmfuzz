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

#[derive(Parser, Clone)]
pub(crate) struct FuelProfileOpts {
    pub(crate) program: PathBuf,
    /// Input files or directories (directories are listed one level deep).
    inputs: Vec<String>,
    #[clap(long, default_value = "2000000000")]
    instruction_limit: u64,
    /// Inputs larger than this are skipped (monitor-cov uses 65535).
    #[clap(long, default_value = "65535")]
    input_size_limit: usize,
    /// Output prefix: writes <out>.inputs.tsv, <out>.funcs.tsv and <out>.sites.tsv.
    #[clap(long)]
    out: PathBuf,
    /// Run every input on a fresh instance (re-running the initializers, whose work then shows
    /// up in the profile) instead of the persistent instance the fuzzer uses.
    #[clap(long)]
    fresh: bool,
    /// Timing mode: no profiling passes; run every input this many times back to back and
    /// write <out>.time.tsv with the fuel, bulk fuel and min/median wall time per input.
    #[clap(long)]
    time_reps: Option<usize>,
}

fn fuel_time(mod_spec: std::sync::Arc<ModuleSpec>, opts: &FuelProfileOpts, reps: usize) {
    let paths = super::gather_inputs_paths(&None, &opts.inputs, true);
    let mut sess = JitFuzzingSession::builder(mod_spec.clone())
        .passes_generator(std::sync::Arc::new(crate::jit::EmptyPassesGen))
        .instruction_limit(Some(opts.instruction_limit))
        .build();
    let mut out =
        std::io::BufWriter::new(std::fs::File::create(opts.out.with_extension("time.tsv")).unwrap());
    writeln!(out, "input\tsize\tresult\tfuel\tbulk_fuel\tns_min\tns_med").unwrap();
    let mut stats = Stats::default();
    let empty = PathBuf::from("<empty>");
    let mut need_warmup = !opts.fresh;
    for path in std::iter::once(None).chain(paths.iter().map(Some)) {
        let input = match path {
            None => Vec::new(),
            Some(p) => match std::fs::read(p) {
                Ok(i) if i.len() <= opts.input_size_limit => i,
                _ => continue,
            },
        };
        let mut ns = Vec::with_capacity(reps);
        let (mut fuel, mut bulk, mut result) = (0, 0, "ok");
        for _ in 0..reps.max(1) {
            if need_warmup {
                sess.run_reusable_fresh(&[], false, &mut stats);
            }
            let bulk0 = BULK_FUEL.get();
            let start = Instant::now();
            let res = if opts.fresh {
                sess.run_reusable_fresh(&input, false, &mut stats)
            } else {
                sess.run_reusable(&input, false, &mut stats)
            };
            ns.push(start.elapsed().as_nanos() as u64);
            bulk = BULK_FUEL.get() - bulk0;
            fuel = fuel_used(&sess);
            result = trap_name(&res.trap_kind);
            need_warmup = !opts.fresh && res.trap_kind.is_some();
        }
        ns.sort_unstable();
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            path.unwrap_or(&empty).display(),
            input.len(),
            result,
            fuel,
            bulk,
            ns[0],
            ns[ns.len() / 2]
        )
        .unwrap();
    }
    out.flush().unwrap();
}

#[derive(Default, Clone, Copy)]
struct Agg {
    sum: u64,
    min: u64,
    max: u64,
    present: u32,
}

impl Agg {
    fn add(&mut self, v: u64, first: bool) {
        if first {
            self.min = v;
        }
        self.sum += v;
        self.min = self.min.min(v);
        self.max = self.max.max(v);
        if v > 0 {
            self.present += 1;
        }
    }
}

/// Where the fuel of a set of inputs goes: self fuel per function (executed operators from the
/// basic-block hit counts, and everything charged in the function's frames incl. bulk memory),
/// inclusive fuel per function and per call site, aggregated over all inputs. The empty input is
/// run first and reported separately as the input-independent floor.
pub(crate) fn fuel_profile(mod_spec: std::sync::Arc<ModuleSpec>, opts: FuelProfileOpts) {
    if let Some(reps) = opts.time_reps {
        return fuel_time(mod_spec, &opts, reps);
    }
    use crate::instrumentation::{CallSiteFuelPass, FunctionFuelPass, Passes};
    use crate::jit::PassesGen;

    #[derive(Debug)]
    struct Gen(std::sync::Arc<ModuleSpec>);
    impl PassesGen for Gen {
        fn generate_passes(&self) -> Passes {
            let mut p = Passes::empty();
            p.push_kv(PerffuzzFunctionPass::new(&self.0, |_| true));
            p.push_kv(PerffuzzBBPass::new(&self.0, |_| true));
            p.push_kv(CallSiteFuelPass::new(&self.0));
            p.push_kv(FunctionFuelPass::new(&self.0, false));
            p.push_kv(FunctionFuelPass::new(&self.0, true));
            p
        }
    }

    let paths = super::gather_inputs_paths(&None, &opts.inputs, true);
    let mut sess = JitFuzzingSession::builder(mod_spec.clone())
        .passes_generator(std::sync::Arc::new(Gen(mod_spec.clone())))
        .instruction_limit(Some(opts.instruction_limit))
        .build();
    let view = symbolic::common::ByteView::from_slice(&mod_spec.wasm_binary);
    let object = symbolic::debuginfo::Object::parse(&view).ok();
    let dbg = object.as_ref().and_then(|o| o.debug_session().ok());
    let funcs: Vec<_> = dbg
        .as_ref()
        .map(|s| s.functions().filter_map(|f| f.ok()).collect())
        .unwrap_or_default();
    let op_src = |func: u32, op: usize| -> String {
        let f = &mod_spec.functions[func as usize];
        let Some(&off_rel) = f.operator_offset_rel.get(op) else {
            return String::new();
        };
        let addr = (f.operators_wasm_bin_offset_base + off_rel as usize) as u64;
        resolve(&funcs, addr).unwrap_or_default()
    };
    // basic block sizes (fuel per entry), as charged by the JIT
    let bb_size = |loc: &Location| -> u64 {
        let f = &mod_spec.functions[loc.function as usize];
        let end = f
            .basic_block_starts
            .iter()
            .find(|x| x.0 > loc.index)
            .map(|x| x.0)
            .unwrap_or(f.operators.len() as u32);
        (end - loc.index) as u64
    };

    let nf = mod_spec.functions.len();
    let mut f_calls = vec![0u64; nf];
    let mut f_self_bb = vec![Agg::default(); nf];
    let mut f_self = vec![Agg::default(); nf];
    let mut f_incl = vec![Agg::default(); nf];
    let mut sites: Vec<Location> = Vec::new();
    let mut s_agg: Vec<Agg> = Vec::new();
    let mut s_calls: Vec<u64> = Vec::new();
    let mut out_inputs =
        std::io::BufWriter::new(std::fs::File::create(opts.out.with_extension("inputs.tsv")).unwrap());
    writeln!(
        out_inputs,
        "input\tsize\tresult\tfuel\tbulk_fuel\tattributed\ttop_self_func\ttop_self_fuel\texec_us"
    )
    .unwrap();
    let mut stats = Stats::default();
    let mut n = 0usize;
    let empty = PathBuf::from("<empty>");
    let all = std::iter::once(None).chain(paths.iter().map(Some));
    // Persistent mode (the fuzzer's default): instantiate and run the initializers in a warm-up
    // execution, then run the inputs back to back on the same instance. After a trap the
    // fuzzer re-initialises the instance; do that in another warm-up so the initializers do
    // not land in the next input's profile.
    let mut need_warmup = !opts.fresh;
    for path in all {
        let input = match path {
            None => Vec::new(),
            Some(p) => match std::fs::read(p) {
                Ok(i) if i.len() <= opts.input_size_limit => i,
                _ => continue,
            },
        };
        if need_warmup {
            sess.run_reusable_fresh(&[], false, &mut stats);
        }
        sess.reset_pass_coverage();
        let start = Instant::now();
        let bulk0 = BULK_FUEL.get();
        let res = if opts.fresh {
            sess.run_reusable_fresh(&input, false, &mut stats)
        } else {
            sess.run_reusable(&input, false, &mut stats)
        };
        need_warmup = !opts.fresh && res.trap_kind.is_some();
        let bulk = BULK_FUEL.get() - bulk0;
        let us = start.elapsed().as_micros();
        let fuel = fuel_used(&sess);

        let mut self_bb = vec![0u64; nf];
        for (loc, v) in sess.get_pass::<PerffuzzBBPass>().coverage.iter_saved() {
            let v = **v as u64;
            if v > 0 {
                self_bb[loc.function as usize] += v * bb_size(loc);
            }
        }
        let fpasses = sess.get_passes::<FunctionFuelPass>();
        let raw_pass = fpasses.iter().find(|p| !p.inclusive).unwrap();
        let incl_pass = fpasses.iter().find(|p| p.inclusive).unwrap();
        let mut raw = vec![0u64; nf];
        for (k, v) in raw_pass.coverage.iter_saved() {
            raw[k.0 as usize] = **v;
        }
        let mut incl = vec![0u64; nf];
        for (k, v) in incl_pass.coverage.iter_saved() {
            incl[k.0 as usize] = **v;
        }
        let site_pass = sess.get_pass::<CallSiteFuelPass>();
        if sites.is_empty() {
            sites = site_pass.coverage.iter_saved().map(|(k, _)| *k).collect();
            s_agg = vec![Agg::default(); sites.len()];
            s_calls = vec![0; sites.len()];
        }
        let site_vals: Vec<u64> = site_pass.coverage.iter_saved().map(|(_, v)| **v).collect();
        let mut self_total = raw.clone();
        for (loc, &v) in sites.iter().zip(&site_vals) {
            let s = &mut self_total[loc.function as usize];
            *s = s.saturating_sub(v);
        }
        let attributed: u64 = self_total.iter().sum();
        let (top_f, top_v) = self_total
            .iter()
            .enumerate()
            .max_by_key(|&(_, v)| *v)
            .map(|(i, v)| (i, *v))
            .unwrap_or((0, 0));
        writeln!(
            out_inputs,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            path.unwrap_or(&empty).display(),
            input.len(),
            trap_name(&res.trap_kind),
            fuel,
            bulk,
            attributed,
            mod_spec.functions[top_f].symbol,
            top_v,
            us
        )
        .unwrap();
        if path.is_none() {
            continue;
        }
        let first = n == 0;
        n += 1;
        for (k, v) in sess.get_pass::<PerffuzzFunctionPass>().coverage.iter_saved() {
            f_calls[k.0 as usize] += **v as u64;
        }
        for i in 0..nf {
            f_self_bb[i].add(self_bb[i], first);
            f_self[i].add(self_total[i], first);
            f_incl[i].add(incl[i], first);
        }
        for (i, &v) in site_vals.iter().enumerate() {
            s_agg[i].add(v, first);
        }
        // call counts per site are not tracked; count inputs instead
        for (i, &v) in site_vals.iter().enumerate() {
            if v > 0 {
                s_calls[i] += 1;
            }
        }
    }
    out_inputs.flush().unwrap();

    let mut out_funcs =
        std::io::BufWriter::new(std::fs::File::create(opts.out.with_extension("funcs.tsv")).unwrap());
    writeln!(
        out_funcs,
        "func\tsymbol\tcalls\tself_bb\tself\tself_min\tself_max\tincl\tincl_min\tincl_max\tn_present\tn_inputs\tsrc"
    )
    .unwrap();
    let mut order: Vec<usize> = (0..nf).filter(|&i| f_incl[i].sum > 0 || f_self[i].sum > 0).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(f_self[i].sum.max(f_incl[i].sum)));
    for i in order {
        let f = &mod_spec.functions[i];
        writeln!(
            out_funcs,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            i,
            f.symbol,
            f_calls[i],
            f_self_bb[i].sum,
            f_self[i].sum,
            f_self[i].min,
            f_self[i].max,
            f_incl[i].sum,
            f_incl[i].min,
            f_incl[i].max,
            f_incl[i].present.max(f_self[i].present),
            n,
            op_src(i as u32, 0)
        )
        .unwrap();
    }
    out_funcs.flush().unwrap();

    let mut out_sites =
        std::io::BufWriter::new(std::fs::File::create(opts.out.with_extension("sites.tsv")).unwrap());
    writeln!(
        out_sites,
        "caller\tip\tcaller_symbol\tcallee\tincl\tincl_min\tincl_max\tn_present\tn_inputs\tsrc"
    )
    .unwrap();
    let mut order: Vec<usize> = (0..sites.len()).filter(|&i| s_agg[i].sum > 0).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(s_agg[i].sum));
    for i in order {
        let loc = sites[i];
        let f = &mod_spec.functions[loc.function as usize];
        let callee = match &f.operators[loc.index as usize] {
            crate::ir::WFOperator::Control(crate::ir::ControlInstruction::Call {
                function_index,
                ..
            }) => mod_spec.functions[*function_index as usize].symbol.clone(),
            _ => "<indirect>".to_string(),
        };
        writeln!(
            out_sites,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            loc.function,
            loc.index,
            f.symbol,
            callee,
            s_agg[i].sum,
            s_agg[i].min,
            s_agg[i].max,
            s_calls[i],
            n,
            op_src(loc.function, loc.index as usize)
        )
        .unwrap();
    }
    out_sites.flush().unwrap();
    eprintln!("fuel-profile: {n} inputs");
}
