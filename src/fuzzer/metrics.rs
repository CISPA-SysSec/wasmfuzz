use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::jit::Stats;

/// Cadence at which a worker may dump `$WASMFUZZ_METRICS_JSON`. Bound on
/// staleness in the monitor-cov-folded `LogEvent.stats`.
pub(crate) const METRICS_TICK: Duration = Duration::from_secs(10);

static SESSION_START: OnceLock<Instant> = OnceLock::new();

/// Mark the start of a `fuzz()` session for `wall_elapsed_ns` in snapshots.
pub(crate) fn init_session() {
    let _ = SESSION_START.get_or_init(Instant::now);
}

pub(crate) fn session_elapsed() -> Duration {
    SESSION_START.get().map(|t| t.elapsed()).unwrap_or_default()
}

/// Resolve `$WASMFUZZ_METRICS_JSON` once per process. Returns `None` if unset
/// or empty.
pub(crate) fn metrics_path() -> Option<&'static PathBuf> {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        std::env::var_os("WASMFUZZ_METRICS_JSON")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    })
    .as_ref()
}

#[derive(Default)]
struct AccumulatorInner {
    metrics_updates: usize,

    reusable_stage_executions: usize,
    tracing_stage_executions: usize,
    traps: usize,
    traps_gone_wrong: usize,
    unstable_instrumentation_counter: usize,
    bus_rx: usize,
    bus_tx: usize,
    finds_own: usize,
    finds_imported: usize,
    wall_mutate_ns: u64,
    wall_reusable_ns: u64,
    wall_tracing_ns: u64,
    wall_initial_codegen_ns: u64,
    wall_rehydrate_ns: u64,
    exhaustive_execs: usize,
    exhaustive_finds: usize,
    lod_mutations: usize,
    non_lod_mutations: usize,
    lod_finds: usize,
    non_lod_finds: usize,

    workers_started: usize,
    workers_completed: usize,
    found_crashes: bool,

    corpus_count: usize,
    solutions_count: usize,
    exhaustive_queue_len: usize,
    stage_depth: usize,
    lod_corpus_shapes: usize,
    lod_corpus_entries: usize,
    lod_engine: Option<&'static str>,
    orc_edges: usize,
}

/// Process-wide accumulator of fuzzer counters. Each worker periodically
/// merges its [`Stats`] delta-since-last-merge into this via
/// [`Self::merge_delta`]; workers come and go but the accumulator persists
/// for the whole `fuzz()` session. Any worker may snapshot this and write
/// it atomically to `$WASMFUZZ_METRICS_JSON` via [`Self::dump_if_enabled`]
/// when its run ends or [`METRICS_TICK`] elapses.
pub(crate) struct Accumulator {
    inner: Mutex<AccumulatorInner>,
}

impl Default for Accumulator {
    fn default() -> Self {
        Self {
            inner: Mutex::new(AccumulatorInner::default()),
        }
    }
}

impl Accumulator {
    /// Add `delta` to the accumulated counter totals. Workers call this with
    /// their `(stats_now - last_merged)` delta; pass the same `Stats` snapshot
    /// in as `last_merged` next time.
    pub fn merge_delta(&self, delta: StatsDelta) {
        let mut inner = self.inner.lock().unwrap();
        inner.metrics_updates += 1;
        inner.reusable_stage_executions += delta.reusable_stage_executions;
        inner.tracing_stage_executions += delta.tracing_stage_executions;
        inner.traps += delta.traps;
        inner.traps_gone_wrong += delta.traps_gone_wrong;
        inner.unstable_instrumentation_counter += delta.unstable_instrumentation_counter;
        inner.bus_rx += delta.bus_rx;
        inner.bus_tx += delta.bus_tx;
        inner.finds_own += delta.finds_own;
        inner.finds_imported += delta.finds_imported;
        inner.wall_mutate_ns += delta.wall_mutate_ns;
        inner.wall_reusable_ns += delta.wall_reusable_ns;
        inner.wall_tracing_ns += delta.wall_tracing_ns;
        inner.wall_initial_codegen_ns += delta.wall_initial_codegen_ns;
        inner.wall_rehydrate_ns += delta.wall_rehydrate_ns;
        inner.exhaustive_execs += delta.exhaustive_execs;
        inner.exhaustive_finds += delta.exhaustive_finds;
        inner.lod_mutations += delta.lod_mutations;
        inner.non_lod_mutations += delta.non_lod_mutations;
        inner.lod_finds += delta.lod_finds;
        inner.non_lod_finds += delta.non_lod_finds;
    }

    /// Update orchestrator session edge coverage (from `orc.rs`'s codecov sess).
    pub fn update_orc_edges(&self, edges: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.metrics_updates += 1;
        inner.orc_edges = edges;
    }

    pub fn note_worker_started(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.metrics_updates += 1;
        inner.workers_started += 1;
    }

    pub fn note_worker_completed(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.metrics_updates += 1;
        inner.workers_completed += 1;
    }

    pub fn note_crash(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.metrics_updates += 1;
        inner.found_crashes = true;
    }

    /// Update the "last-seen active worker" fields. Lossy by design; the
    /// snapshot just wants a recent view.
    pub fn update_active_state(
        &self,
        corpus_count: usize,
        solutions_count: usize,
        exhaustive_queue_len: usize,
        stage_depth: usize,
        lod_engine: Option<&'static str>,
        lod_corpus: Option<(usize, usize)>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.metrics_updates += 1;
        inner.corpus_count = corpus_count;
        inner.solutions_count = solutions_count;
        inner.exhaustive_queue_len = exhaustive_queue_len;
        inner.stage_depth = stage_depth;
        if let Some((shapes, entries)) = lod_corpus {
            inner.lod_corpus_shapes = shapes;
            inner.lod_corpus_entries = entries;
        }
        if let Some(engine) = lod_engine {
            inner.lod_engine = Some(engine);
        }
    }

    /// Snapshot all counters into a serializable struct and write it
    /// atomically to `$WASMFUZZ_METRICS_JSON` (if set). No-op when the env var
    /// is unset.
    pub fn dump_if_enabled(&self, wall_elapsed: Duration) {
        let Some(path) = metrics_path() else {
            return;
        };
        let snap = self.snapshot(wall_elapsed);
        write_atomic(path, &snap);
    }

    fn snapshot(&self, wall_elapsed: Duration) -> MetricsSnapshot {
        let inner = self.inner.lock().unwrap();
        MetricsSnapshot {
            process_rss_bytes: current_process_rss_bytes(),
            wall_elapsed_ns: wall_elapsed.as_nanos().min(u64::MAX as u128) as u64,
            metrics_updates: inner.metrics_updates,
            reusable_stage_executions: inner.reusable_stage_executions,
            tracing_stage_executions: inner.tracing_stage_executions,
            traps: inner.traps,
            traps_gone_wrong: inner.traps_gone_wrong,
            unstable_instrumentation_counter: inner.unstable_instrumentation_counter,
            bus_rx: inner.bus_rx,
            bus_tx: inner.bus_tx,
            finds_own: inner.finds_own,
            finds_imported: inner.finds_imported,
            wall_mutate_ns: inner.wall_mutate_ns,
            wall_reusable_ns: inner.wall_reusable_ns,
            wall_tracing_ns: inner.wall_tracing_ns,
            wall_initial_codegen_ns: inner.wall_initial_codegen_ns,
            wall_rehydrate_ns: inner.wall_rehydrate_ns,
            exhaustive_execs: inner.exhaustive_execs,
            exhaustive_finds: inner.exhaustive_finds,
            workers_started: inner.workers_started,
            workers_completed: inner.workers_completed,
            found_crashes: inner.found_crashes,
            corpus_count: inner.corpus_count,
            solutions_count: inner.solutions_count,
            exhaustive_queue_len: inner.exhaustive_queue_len,
            stage_depth: inner.stage_depth,
            lod_engine: inner.lod_engine,
            lod_corpus_shapes: inner.lod_corpus_shapes,
            lod_corpus_entries: inner.lod_corpus_entries,
            orc_edges: inner.orc_edges,
            lod_mutations: inner.lod_mutations,
            non_lod_mutations: inner.non_lod_mutations,
            lod_finds: inner.lod_finds,
            non_lod_finds: inner.non_lod_finds,
        }
    }
}

/// Per-Stats-field delta the worker computes between merges.
#[derive(Default, Debug)]
pub(crate) struct StatsDelta {
    pub reusable_stage_executions: usize,
    pub tracing_stage_executions: usize,
    pub traps: usize,
    pub traps_gone_wrong: usize,
    pub unstable_instrumentation_counter: usize,
    pub bus_rx: usize,
    pub bus_tx: usize,
    pub finds_own: usize,
    pub finds_imported: usize,
    pub wall_mutate_ns: u64,
    pub wall_reusable_ns: u64,
    pub wall_tracing_ns: u64,
    pub wall_initial_codegen_ns: u64,
    pub wall_rehydrate_ns: u64,
    pub exhaustive_execs: usize,
    pub exhaustive_finds: usize,
    pub lod_mutations: usize,
    pub non_lod_mutations: usize,
    pub lod_finds: usize,
    pub non_lod_finds: usize,
}

impl StatsDelta {
    /// `current - previous`. Saturating in the unlikely case the worker
    /// resets a counter mid-session (shouldn't happen — `Stats` is monotonic
    /// for the worker's lifetime).
    pub fn between(previous: &Stats, current: &Stats) -> Self {
        Self {
            reusable_stage_executions: current
                .reusable_stage_executions
                .saturating_sub(previous.reusable_stage_executions),
            tracing_stage_executions: current
                .tracing_stage_executions
                .saturating_sub(previous.tracing_stage_executions),
            traps: current.traps.saturating_sub(previous.traps),
            traps_gone_wrong: current
                .traps_gone_wrong
                .saturating_sub(previous.traps_gone_wrong),
            unstable_instrumentation_counter: current
                .unstable_instrumentation_counter
                .saturating_sub(previous.unstable_instrumentation_counter),
            bus_rx: current.bus_rx.saturating_sub(previous.bus_rx),
            bus_tx: current.bus_tx.saturating_sub(previous.bus_tx),
            finds_own: current.finds_own.saturating_sub(previous.finds_own),
            finds_imported: current
                .finds_imported
                .saturating_sub(previous.finds_imported),
            wall_mutate_ns: current
                .wall_mutate_ns
                .saturating_sub(previous.wall_mutate_ns),
            wall_reusable_ns: current
                .wall_reusable_ns
                .saturating_sub(previous.wall_reusable_ns),
            wall_tracing_ns: current
                .wall_tracing_ns
                .saturating_sub(previous.wall_tracing_ns),
            wall_initial_codegen_ns: current
                .wall_initial_codegen_ns
                .saturating_sub(previous.wall_initial_codegen_ns),
            wall_rehydrate_ns: current
                .wall_rehydrate_ns
                .saturating_sub(previous.wall_rehydrate_ns),
            exhaustive_execs: current
                .exhaustive_execs
                .saturating_sub(previous.exhaustive_execs),
            exhaustive_finds: current
                .exhaustive_finds
                .saturating_sub(previous.exhaustive_finds),
            lod_mutations: current.lod_mutations.saturating_sub(previous.lod_mutations),
            non_lod_mutations: current
                .non_lod_mutations
                .saturating_sub(previous.non_lod_mutations),
            lod_finds: current.lod_finds.saturating_sub(previous.lod_finds),
            non_lod_finds: current.non_lod_finds.saturating_sub(previous.non_lod_finds),
        }
    }
}

/// Current process RSS in bytes, sampled at snapshot time. Linux only
/// (`/proc/self/statm` resident pages × page size).
#[cfg(target_os = "linux")]
fn current_process_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    let page_size = rustix::param::page_size() as u64;
    Some(resident_pages.saturating_mul(page_size))
}

#[cfg(not(target_os = "linux"))]
fn current_process_rss_bytes() -> Option<u64> {
    None
}

/// JSON payload written to `$WASMFUZZ_METRICS_JSON`. Flattens the
/// accumulated [`Stats`] counters plus worker-lifecycle and last-seen state
/// fields. Folded into per-snapshot `LogEvent.stats` by `monitor-cov`.
#[derive(Debug, Serialize)]
pub(crate) struct MetricsSnapshot {
    /// Process RSS in bytes at snapshot time (`None` on non-Linux).
    pub process_rss_bytes: Option<u64>,
    pub wall_elapsed_ns: u64,
    pub metrics_updates: usize,
    pub reusable_stage_executions: usize,
    pub tracing_stage_executions: usize,
    pub traps: usize,
    pub traps_gone_wrong: usize,
    pub unstable_instrumentation_counter: usize,
    pub bus_rx: usize,
    pub bus_tx: usize,
    pub finds_own: usize,
    pub finds_imported: usize,
    pub wall_mutate_ns: u64,
    pub wall_reusable_ns: u64,
    pub wall_tracing_ns: u64,
    pub wall_initial_codegen_ns: u64,
    pub wall_rehydrate_ns: u64,
    pub exhaustive_execs: usize,
    pub exhaustive_finds: usize,
    pub workers_started: usize,
    pub workers_completed: usize,
    pub found_crashes: bool,
    pub corpus_count: usize,
    pub solutions_count: usize,
    pub exhaustive_queue_len: usize,
    pub stage_depth: usize,
    pub lod_engine: Option<&'static str>,
    pub lod_corpus_shapes: usize,
    pub lod_corpus_entries: usize,
    pub orc_edges: usize,
    pub lod_mutations: usize,
    pub non_lod_mutations: usize,
    pub lod_finds: usize,
    pub non_lod_finds: usize,
}

/// Atomically write `snap` as JSON to `$WASMFUZZ_METRICS_JSON`: write to a
/// sibling `.tmp` file, then `rename` over the final path. Best-effort: I/O
/// errors are logged once and otherwise ignored so the fuzzer hot path keeps
/// running.
fn write_atomic(path: &PathBuf, snap: &MetricsSnapshot) {
    let json = match serde_json::to_vec(snap) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[wasmfuzz-metrics] serialize failed: {e}");
            return;
        }
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, &json) {
        eprintln!("[wasmfuzz-metrics] write {tmp:?} failed: {e}");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        eprintln!("[wasmfuzz-metrics] rename {tmp:?} -> {path:?} failed: {e}");
    }
}
