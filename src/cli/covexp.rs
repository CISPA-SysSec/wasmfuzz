use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use covexp_core::import::{BlockId, EdgeId, FileId, GroupId, Importer, SourceLoc};
use covexp_core::model::EdgeKind;
use covexp_core::rusqlite::Connection;
use symbolic::debuginfo::Object;

use crate::instrumentation::{
    BBCoveragePass, CallSiteCoveragePass, Edge, EdgeCoveragePass, FuncIdx, FunctionCoveragePass,
};
use crate::ir::{InsnIdx, Location, ModuleSpec, debuginfo_helper::resolve_source_location};
use crate::jit::JitFuzzingSession;
use crate::{HashMap, HashSet};

#[derive(Parser)]
pub(crate) struct CovexpImportOpts {
    pub program: PathBuf,
    #[clap(long)]
    pub seed_files: Vec<String>,
    #[clap(long)]
    pub dir: Option<String>,
    /// Database to import into. One that already holds an import of this module gets
    /// `--group` added to it, so several corpora (the arms of an experiment) share a database.
    #[clap(long, default_value = "covexp.db")]
    pub db: PathBuf,
    /// Group the inputs' testcases go into.
    #[clap(long, default_value = "wasmfuzz")]
    pub group: String,
    /// Allow `--group` to name a group the database already has; the inputs are added to it.
    #[clap(long)]
    pub extend_group: bool,
    /// Prefix for the per-input testcase labels. Defaults to the input's file name.
    #[clap(long)]
    pub testcase_label: Option<String>,
    /// Empty an existing database at `--db` before importing.
    #[clap(long)]
    pub reset: bool,
    #[clap(long)]
    pub source_root: Option<PathBuf>,
    #[clap(long)]
    pub strip_prefix: Option<String>,
}

fn loc(function: u32, block: InsnIdx) -> Location {
    Location {
        function,
        index: block.0,
    }
}

/// The parts of a structural import that coverage bitmaps are built from.
///
/// covexp blocks are the fuzzer's basic blocks, split once more after every
/// instrumented call: a call that never returns (a panic, say) must not credit
/// the rest of its basic block. Blocks are keyed by the `Location` of their
/// first instruction.
#[derive(Default)]
struct Structure {
    /// DB edge for every instrumented (critical) CFG edge.
    instrumented: HashMap<Edge, EdgeId>,
    /// Edges the edge pass doesn't instrument, as `(from, to, edge)`: a block
    /// with a single successor gets no counter of its own, so the edge is
    /// covered iff both of its endpoints ran. Function entry markers are in
    /// here too, as edges from a block to itself.
    block_implied: Vec<(Location, Location, EdgeId)>,
    /// Edges covered iff the call instruction at the location ran: direct
    /// calls into the callee's entry block.
    call_reached: Vec<(Location, EdgeId)>,
    /// Edges covered iff the call at the location returned: the fallthrough
    /// from a call's block into the one after it.
    call_returned: Vec<(Location, EdgeId)>,
    /// Blocks that start right after a call (and aren't basic blocks of the
    /// fuzzer's own): they ran iff that call returned.
    after_call: HashMap<Location, Location>,
    /// Entry block of each function, to resolve `FunctionCoveragePass` keys.
    entry_blocks: HashMap<FuncIdx, Location>,
}

/// Which of a session's coverage bits a testcase is made of.
#[derive(Clone, Copy)]
pub(crate) enum Observed {
    /// Everything the session's passes have saved so far.
    Accumulated,
    /// Only the latest run. The caller must have cleared the passes' per-run
    /// bits (`reset_pass_coverage_keep_saved`) right before it.
    LastRun,
}

fn covered_keys<K: Ord + Clone>(
    coverage: &crate::instrumentation::CoverageBitset<K>,
    observed: Observed,
) -> Vec<K> {
    let bits = match observed {
        Observed::Accumulated => &coverage.saved,
        Observed::LastRun => &coverage.entries,
    };
    bits.iter_ones().map(|i| coverage.keys[i].clone()).collect()
}

/// A covexp database with one module's structure imported into it.
///
/// Functions, blocks and edges are written once, when the sink is opened;
/// every testcase afterwards only appends a coverage bitmap. The maps in
/// [`Structure`] translate a fuzzing session's pass coverage back into the
/// edge IDs those bitmaps are made of.
pub(crate) struct CovexpSink {
    conn: Connection,
    group: GroupId,
    structure: Structure,
    /// Testcases waiting for [`CovexpSink::flush`].
    pending: Vec<PendingTestcase>,
}

struct PendingTestcase {
    label: Option<String>,
    edges: Vec<EdgeId>,
    input: Option<Vec<u8>>,
}

impl CovexpSink {
    /// Open `db` and import `mod_spec`'s structure into it.
    ///
    /// A database that already holds an import of this very module is appended
    /// to: `group` becomes one more group next to the ones already there, which
    /// is how the arms of an experiment end up comparable in one database. A
    /// group of that name that is already there is refused unless `extend_group`
    /// is set, so running an import twice doesn't double its testcases. An
    /// import of anything else is refused unless `reset` is set, in which case
    /// the database is emptied in place: unlinking and recreating the file
    /// would leave a running `covexp serve` reading the deleted one.
    pub(crate) fn open(
        db: &Path,
        mod_spec: &ModuleSpec,
        group: &str,
        source_root: Option<&Path>,
        strip_prefix: Option<&str>,
        reset: bool,
        extend_group: bool,
    ) -> Result<Self, String> {
        let conn = covexp_core::schema::open(db.to_string_lossy().as_ref())
            .map_err(|err| format!("failed to open covexp db {}: {err:#}", db.display()))?;
        // Re-importing the structure would duplicate every function, block and
        // edge in the database rather than update them.
        let has_import = !covexp_core::query::list_functions(&conn)
            .map_err(|err| format!("failed to read covexp db {}: {err:#}", db.display()))?
            .is_empty();
        if has_import {
            if !reset {
                return Self::append(
                    conn,
                    db,
                    mod_spec,
                    group,
                    source_root,
                    strip_prefix,
                    extend_group,
                );
            }
            clear_database(&conn)
                .map_err(|err| format!("failed to reset covexp db {}: {err}", db.display()))?;
        }
        Ok(Self::attach(
            conn,
            mod_spec,
            group,
            source_root,
            strip_prefix,
        ))
    }

    /// Add `group` to a database that already holds an import.
    ///
    /// The structural import is deterministic and always starts from an empty
    /// database, so replaying it into a scratch one yields the very row IDs the
    /// first import got, if it was of this module with these path options. The
    /// fingerprints say whether it was.
    fn append(
        conn: Connection,
        db: &Path,
        mod_spec: &ModuleSpec,
        group: &str,
        source_root: Option<&Path>,
        strip_prefix: Option<&str>,
        extend_group: bool,
    ) -> Result<Self, String> {
        let scratch = covexp_core::schema::open_in_memory()
            .map_err(|err| format!("failed to create scratch covexp db: {err:#}"))?;
        let structure = import_structure(&scratch, mod_spec, source_root, strip_prefix);
        let fingerprint = |conn: &Connection| {
            covexp_core::query::structure_fingerprint(conn)
                .map_err(|err| format!("failed to read covexp db {}: {err:#}", db.display()))
        };
        if fingerprint(&scratch)? != fingerprint(&conn)? {
            return Err(format!(
                "covexp db {} already contains an import of a different module (or of this one \
                 with other --source-root/--strip-prefix): reset it or point at a fresh file",
                db.display()
            ));
        }
        let groups = covexp_core::query::list_groups(&conn)
            .map_err(|err| format!("failed to read covexp db {}: {err:#}", db.display()))?;
        if !extend_group && groups.iter().any(|existing| existing.name == group) {
            return Err(format!(
                "covexp db {} already has a group {group:?}: pick another --group, or pass \
                 --extend-group to add to it",
                db.display()
            ));
        }
        let group = Importer::new(&conn)
            .add_group(group)
            .map_err(|err| format!("failed to add group to covexp db {}: {err:#}", db.display()))?;
        Ok(Self {
            conn,
            group,
            structure,
            pending: Vec::new(),
        })
    }

    pub(crate) fn attach(
        conn: Connection,
        mod_spec: &ModuleSpec,
        group: &str,
        source_root: Option<&Path>,
        strip_prefix: Option<&str>,
    ) -> Self {
        let structure = import_structure(&conn, mod_spec, source_root, strip_prefix);
        let group = Importer::new(&conn).add_group(group).unwrap();
        Self {
            conn,
            group,
            structure,
            pending: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// What the session's passes say is covered, as covexp edge IDs.
    fn covered_edges(&self, sess: &JitFuzzingSession, observed: Observed) -> HashSet<EdgeId> {
        let calls = covered_keys(&sess.get_pass::<CallSiteCoveragePass>().coverage, observed);
        let reached = calls
            .iter()
            .filter(|call| !call.returned)
            .map(|call| call.location)
            .collect::<HashSet<Location>>();
        let returned = calls
            .iter()
            .filter(|call| call.returned)
            .map(|call| call.location)
            .collect::<HashSet<Location>>();

        let mut covered_blocks =
            covered_keys(&sess.get_pass::<BBCoveragePass>().coverage, observed)
                .into_iter()
                .collect::<HashSet<Location>>();
        for func in covered_keys(&sess.get_pass::<FunctionCoveragePass>().coverage, observed) {
            if let Some(entry) = self.structure.entry_blocks.get(&func) {
                covered_blocks.insert(*entry);
            }
        }
        for (block, site) in &self.structure.after_call {
            if returned.contains(site) {
                covered_blocks.insert(*block);
            }
        }

        let mut edges = HashSet::<EdgeId>::default();
        for key in covered_keys(&sess.get_pass::<EdgeCoveragePass>().coverage, observed) {
            if let Some(&edge_id) = self.structure.instrumented.get(&key) {
                edges.insert(edge_id);
            }
        }
        for (from, to, edge_id) in &self.structure.block_implied {
            if covered_blocks.contains(from) && covered_blocks.contains(to) {
                edges.insert(*edge_id);
            }
        }
        for (site, edge_id) in &self.structure.call_reached {
            if reached.contains(site) {
                edges.insert(*edge_id);
            }
        }
        for (site, edge_id) in &self.structure.call_returned {
            if returned.contains(site) {
                edges.insert(*edge_id);
            }
        }
        edges
    }

    /// Record the session's coverage as one testcase, written right away.
    pub(crate) fn add_testcase(
        &mut self,
        sess: &JitFuzzingSession,
        observed: Observed,
        label: Option<&str>,
        input: Option<&[u8]>,
    ) {
        self.queue_testcase(sess, observed, label, input);
        self.flush();
    }

    /// Record the session's coverage as one testcase on the next [`flush`],
    /// so a burst of them shares a transaction.
    ///
    /// [`flush`]: CovexpSink::flush
    pub(crate) fn queue_testcase(
        &mut self,
        sess: &JitFuzzingSession,
        observed: Observed,
        label: Option<&str>,
        input: Option<&[u8]>,
    ) {
        let edges = self.covered_edges(sess, observed).into_iter().collect();
        self.pending.push(PendingTestcase {
            label: label.map(str::to_owned),
            edges,
            input: input.map(<[u8]>::to_vec),
        });
    }

    pub(crate) fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let tx = self.conn.unchecked_transaction().unwrap();
        let imp = Importer::new(&tx);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        for PendingTestcase {
            label,
            edges,
            input,
        } in self.pending.drain(..)
        {
            let testcase = imp
                .add_testcase(self.group, label.as_deref(), Some(timestamp), &edges)
                .unwrap();
            if let Some(input) = input {
                imp.set_testcase_input(testcase, &input).unwrap();
            }
        }
        tx.commit().unwrap();
    }
}

/// Delete every row in the database, keeping its schema.
fn clear_database(conn: &Connection) -> covexp_core::rusqlite::Result<()> {
    let tables = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    // Rows reference each other; the order they're deleted in shouldn't matter.
    conn.execute_batch("PRAGMA foreign_keys = OFF")?;
    let tx = conn.unchecked_transaction()?;
    for table in &tables {
        tx.execute(
            &format!("DELETE FROM \"{}\"", table.replace('"', "\"\"")),
            [],
        )?;
    }
    let has_sequence = tx
        .prepare("SELECT 1 FROM sqlite_master WHERE name = 'sqlite_sequence'")?
        .exists([])?;
    if has_sequence {
        tx.execute("DELETE FROM sqlite_sequence", [])?;
    }
    tx.commit()?;
    conn.execute_batch("PRAGMA foreign_keys = ON")
}

/// Import functions, blocks and edges for `mod_spec`.
///
/// Edges come from the module's CFG, not from the fuzzer's instrumentation:
/// wasmfuzz only instruments *critical* edges (those leaving a block with more
/// than one successor), but the uninstrumented ones are still real control flow
/// and their coverage follows their endpoint blocks.
fn import_structure(
    conn: &Connection,
    mod_spec: &ModuleSpec,
    source_root: Option<&Path>,
    strip_prefix: Option<&str>,
) -> Structure {
    let tx = conn.unchecked_transaction().unwrap();
    let imp = Importer::new(&tx);

    let mut files = collect_embedded_sources(mod_spec);
    let mut file_ids = HashMap::<String, FileId>::default();
    for (path, maybe_content) in files.drain() {
        let normalized_path = normalize_path(path.as_str(), strip_prefix);
        if normalized_path.is_empty() {
            continue;
        }
        let content =
            maybe_content.unwrap_or_else(|| read_source(normalized_path.as_str(), source_root));
        let file_id = imp
            .add_source_file(normalized_path.as_str(), content.as_str())
            .unwrap();
        file_ids.insert(normalized_path, file_id);
    }

    let mut structure = Structure::default();
    let mut block_ids = HashMap::<Location, BlockId>::default();
    // Per function: sorted covexp block starts, and the block each operator is in.
    let mut func_blocks = Vec::<(Vec<InsnIdx>, Vec<InsnIdx>)>::new();

    for func in &mod_spec.functions {
        let func_name = func._symbol.as_deref().unwrap_or(func.symbol.as_str());
        let op_count = func.operator_offset_rel.len();

        let mut starts = func
            .basic_block_starts
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for (site, _) in CallSiteCoveragePass::instrumented_sites(mod_spec, func) {
            let after = site.inc();
            if after.i() < op_count && starts.insert(after) {
                structure
                    .after_call
                    .insert(loc(func.idx, after), loc(func.idx, site));
            }
        }
        let ordered_blocks = starts.into_iter().collect::<Vec<_>>();
        let mut operator_block = Vec::with_capacity(op_count);
        let mut next = ordered_blocks.iter().peekable();
        let mut current = InsnIdx(0);
        for op_idx in 0..op_count {
            if next.peek().is_some_and(|start| start.i() == op_idx) {
                current = *next.next().unwrap();
            }
            operator_block.push(current);
        }

        let mut first_file = None;
        let mut start_line = None;
        let mut end_line = None;
        // The outermost frame of any instruction's inline stack is the function
        // itself, so it names the file the function is actually defined in.
        let mut defining_path = None::<String>;
        let mut block_locations = Vec::new();
        for (block_idx, bb_start) in ordered_blocks.iter().enumerate() {
            let mut locs = Vec::<(String, u32, Option<u32>)>::new();
            let block_start = bb_start.i();
            let block_end = ordered_blocks
                .get(block_idx + 1)
                .map(|next| next.i())
                .unwrap_or(op_count)
                .min(op_count);
            for op_idx in block_start..block_end {
                let addr = func.operators_wasm_bin_offset_base as u64
                    + func.operator_offset_rel[op_idx] as u64;
                let _ = resolve_source_location(mod_spec, addr, |source_locs| {
                    for loc in source_locs {
                        if loc.line() == 0 {
                            continue;
                        }
                        if let Some(file) = loc.file() {
                            let path = normalize_path(file.full_path().as_str(), strip_prefix);
                            if path.is_empty() {
                                continue;
                            }
                            // `source_locs` walks from the innermost inlined
                            // frame outwards, so the last one we see wins.
                            defining_path = Some(path.clone());
                            let candidate = (path, loc.line(), None);
                            if !locs.contains(&candidate) {
                                locs.push(candidate);
                            }
                        }
                    }
                });
            }
            block_locations.push((*bb_start, locs));
        }

        for (_, locs) in &block_locations {
            for (path, _, _) in locs {
                if file_ids.contains_key(path) {
                    continue;
                }
                let content = read_source(path, source_root);
                let id = imp.add_source_file(path, content.as_str()).unwrap();
                file_ids.insert(path.clone(), id);
            }
        }

        // Only lines from the defining file describe this function's extent;
        // lines contributed by inlined callees belong to other files entirely.
        if let Some(defining_path) = defining_path.as_ref() {
            first_file = file_ids.get(defining_path).copied();
            for (_, locs) in &block_locations {
                for (path, line, _) in locs {
                    if path != defining_path {
                        continue;
                    }
                    start_line = Some(start_line.map_or(*line, |x: u32| x.min(*line)));
                    end_line = Some(end_line.map_or(*line, |x: u32| x.max(*line)));
                }
            }
        }

        let function_id = imp
            .add_function(func_name, Some(func_name), first_file, start_line, end_line)
            .unwrap();

        for (ordinal, (bb_start, locs)) in block_locations.into_iter().enumerate() {
            let mut src_locs = Vec::new();
            for (path, line, col) in locs {
                let file_id = *file_ids.get(&path).unwrap();
                src_locs.push(SourceLoc {
                    file: file_id,
                    line,
                    column: col,
                });
            }
            let block = imp
                .add_block(function_id, ordinal as u32, src_locs.as_slice())
                .unwrap();
            block_ids.insert(loc(func.idx, bb_start), block);
        }

        if let Some(entry) = ordered_blocks.first() {
            structure
                .entry_blocks
                .insert(FuncIdx(func.idx), loc(func.idx, *entry));
        }
        func_blocks.push((ordered_blocks, operator_block));
    }

    for (func, (ordered_blocks, operator_block)) in mod_spec.functions.iter().zip(&func_blocks) {
        let mut next_block = HashMap::<InsnIdx, InsnIdx>::default();
        for pair in ordered_blocks.windows(2) {
            next_block.insert(pair[0], pair[1]);
        }
        let block_of = |insn: InsnIdx| operator_block.get(insn.i()).copied();
        let calls =
            CallSiteCoveragePass::instrumented_sites(mod_spec, func).collect::<BTreeMap<_, _>>();

        // Several instruction-level edges can share one block edge (a br_table
        // with two arms into the same block, say); they collapse into one.
        let mut block_edges = BTreeMap::<(InsnIdx, InsnIdx), Vec<(InsnIdx, InsnIdx)>>::new();
        for &(from, to) in &func.cfg_insn_edges {
            let (Some(from_block), Some(to_block)) = (block_of(from), block_of(to)) else {
                continue;
            };
            block_edges
                .entry((from_block, to_block))
                .or_default()
                .push((from, to));
        }
        // Returning from a call falls through into the block after it. When
        // that's also a basic block start, the CFG already has this edge.
        for &site in calls.keys() {
            let after = site.inc();
            if let (Some(from_block), Some(to_block)) = (block_of(site), block_of(after)) {
                let insn_edges = block_edges.entry((from_block, to_block)).or_default();
                if !insn_edges.contains(&(site, after)) {
                    insn_edges.push((site, after));
                }
            }
        }

        for ((from_block, to_block), insn_edges) in block_edges {
            let (Some(&from_id), Some(&to_id)) = (
                block_ids.get(&loc(func.idx, from_block)),
                block_ids.get(&loc(func.idx, to_block)),
            ) else {
                continue;
            };
            let kind = if next_block.get(&from_block) == Some(&to_block) {
                EdgeKind::Fallthrough
            } else {
                EdgeKind::Branch
            };
            let edge_id = imp.add_edge(from_id, to_id, kind).unwrap();

            let mut instrumented = false;
            for &(from, to) in &insn_edges {
                if calls.contains_key(&from) && to == from.inc() {
                    structure.call_returned.push((loc(func.idx, from), edge_id));
                    instrumented = true;
                } else if func.critical_insn_edges.contains(&(from, to)) {
                    structure
                        .instrumented
                        .insert(Edge::new(func.idx, from, to), edge_id);
                    instrumented = true;
                }
            }
            if !instrumented {
                structure.block_implied.push((
                    loc(func.idx, from_block),
                    loc(func.idx, to_block),
                    edge_id,
                ));
            }
        }

        for (&site, &callee) in &calls {
            let Some(callee) = callee else {
                continue;
            };
            let Some(from_block) = block_of(site) else {
                continue;
            };
            let Some(&from_id) = block_ids.get(&loc(func.idx, from_block)) else {
                continue;
            };
            let Some(&callee_entry) = structure.entry_blocks.get(&FuncIdx(callee)) else {
                continue;
            };
            let Some(&to_id) = block_ids.get(&callee_entry) else {
                continue;
            };
            let edge_id = imp.add_edge(from_id, to_id, EdgeKind::DirectCall).unwrap();
            structure.call_reached.push((loc(func.idx, site), edge_id));
        }
    }

    // A block with an incident edge is covered iff one of those edges is: if it
    // ran, it was entered through an in-edge, or it left through an out-edge.
    // Function entries still need a marker of their own, because a function
    // can also be entered through an indirect call, which has no edge in the
    // graph. The marker doubles as the "this function ran" signal, and keeps
    // leaf functions — which own no outgoing edge at all — visible in
    // per-function coverage. Any other block without an edge is dead code
    // (the CFG drops unreachable instructions), and no marker could ever be
    // covered there.
    for (func, (ordered_blocks, _)) in mod_spec.functions.iter().zip(&func_blocks) {
        let Some(entry) = ordered_blocks.first() else {
            continue;
        };
        let entry = loc(func.idx, *entry);
        let Some(&block_id) = block_ids.get(&entry) else {
            continue;
        };
        let edge_id = imp
            .add_edge(block_id, block_id, EdgeKind::Fallthrough)
            .unwrap();
        structure.block_implied.push((entry, entry, edge_id));
    }

    tx.commit().unwrap();
    structure
}

fn collect_embedded_sources(mod_spec: &ModuleSpec) -> HashMap<String, Option<String>> {
    let mut files = HashMap::default();
    let Ok(object) = Object::parse(&mod_spec.wasm_binary) else {
        return files;
    };
    if !object.has_debug_info() {
        return files;
    }
    let Ok(debug_session) = object.debug_session() else {
        return files;
    };
    let Ok(mut entries) = debug_session.files().collect::<Result<Vec<_>, _>>() else {
        return files;
    };
    entries.sort_by_key(|f| (f.abs_path_str(), f.source_str().is_none()));
    entries.dedup_by_key(|f| f.abs_path_str());
    for file in entries {
        files.insert(
            file.abs_path_str(),
            file.source_str().map(|x| x.into_owned()),
        );
    }
    files
}

fn normalize_path(path: &str, strip_prefix: Option<&str>) -> String {
    if let Some(prefix) = strip_prefix
        && let Some(stripped) = path.strip_prefix(prefix)
    {
        return stripped.trim_start_matches('/').to_owned();
    }
    path.to_owned()
}

fn read_source(path: &str, source_root: Option<&Path>) -> String {
    if let Some(root) = source_root {
        let full = root.join(path);
        if let Ok(content) = std::fs::read_to_string(&full) {
            return content;
        }
    }
    std::fs::read_to_string(path).unwrap_or_default()
}

/// One-shot import of a session's accumulated coverage into a fresh database.
pub(crate) fn import_snapshot(
    mod_spec: Arc<ModuleSpec>,
    sess: &JitFuzzingSession,
    db: &Path,
    group: &str,
    testcase_label: Option<&str>,
) {
    let mut sink = CovexpSink::open(db, mod_spec.as_ref(), group, None, None, false, false)
        .unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        });
    sink.add_testcase(sess, Observed::Accumulated, testcase_label, None);
}

// TODO: handle folders-of-inputs
// TODO: handle "foo" and "foo.txt" where "foo.txt" is the debug representation of "foo"
pub(crate) fn run(mod_spec: Arc<ModuleSpec>, input_paths: &[PathBuf], opts: &CovexpImportOpts) {
    let mut sink = CovexpSink::open(
        &opts.db,
        &mod_spec,
        &opts.group,
        opts.source_root.as_deref(),
        opts.strip_prefix.as_deref(),
        opts.reset,
        opts.extend_group,
    )
    .unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });
    let mut stats = crate::jit::Stats::default();
    let mut sess = super::lcov::coverage_session(mod_spec.clone(), &mut stats);

    // Whatever ran while bringing the module up (start function, ctors) belongs
    // to no input, but dropping it would understate the module's coverage.
    sink.add_testcase(&sess, Observed::Accumulated, Some("<module-init>"), None);

    let total = input_paths.len();
    let mut skipped = 0;
    for (i, path) in input_paths.iter().enumerate() {
        print!("[{i}/{total}]\r");
        let input = std::fs::read(path).expect("failed to read input");
        if input.len() > crate::TEST_CASE_SIZE_LIMIT {
            skipped += 1;
            continue;
        }
        // One testcase per input: the point of the per-input split is that
        // `line -> which inputs reach it` and corpus minimization work at all.
        // The session restores its post-initialization snapshot before every
        // run, so each input's coverage is what replaying it alone produces.
        sess.reset_pass_coverage();
        let _res = sess.run(&input, &mut stats);
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
        let label = match opts.testcase_label.as_deref() {
            Some(prefix) => format!("{prefix}:{name}"),
            None => name,
        };
        sink.queue_testcase(
            &sess,
            Observed::Accumulated,
            Some(label.as_str()),
            Some(input.as_slice()),
        );
        if i % 256 == 255 {
            sink.flush();
        }
    }
    sink.flush();
    if total != 0 {
        println!("[{total}/{total}]");
    }
    if skipped != 0 {
        eprintln!(
            "skipped {skipped} input(s) larger than the {} byte test case size limit",
            crate::TEST_CASE_SIZE_LIMIT
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use covexp_core::query;
    use covexp_core::roaring::RoaringBitmap;
    use covexp_core::schema;

    use super::*;
    use crate::cli::lcov::coverage_session;
    use crate::jit::Stats;
    use covexp_core::model::FunctionCfg;

    /// A module whose `LLVMFuzzerTestOneInput(ptr, len)` is `$harness`, with
    /// `body` as its body. The input is written to address 1024.
    fn wat_harness(body: &str) -> Arc<ModuleSpec> {
        let wat = format!(
            r#"(module
                (memory (export "memory") 2)
                (global $flag (mut i32) (i32.const 0))
                (func (export "wasmfuzz_malloc") (param i32) (result i32) i32.const 1024)
                (func $callee nop)
                (func $trap unreachable)
                (func $harness (export "LLVMFuzzerTestOneInput") (param i32 i32) {body}))"#
        );
        Arc::new(ModuleSpec::parse("harness.wasm", &wat::parse_str(wat).unwrap()).unwrap())
    }

    /// One testcase per input, each run on its own in a coverage session.
    fn import_runs(mod_spec: &Arc<ModuleSpec>, inputs: &[&[u8]]) -> CovexpSink {
        let mut stats = Stats::default();
        let mut sess = coverage_session(mod_spec.clone(), &mut stats);
        let mut sink = CovexpSink::attach(
            schema::open_in_memory().unwrap(),
            mod_spec,
            "test",
            None,
            None,
        );
        for input in inputs {
            sess.reset_pass_coverage();
            let _ = sess.run(input, &mut stats);
            sink.add_testcase(&sess, Observed::Accumulated, None, Some(input));
        }
        sink
    }

    /// `$harness`'s CFG, with the union of every testcase's coverage.
    fn harness_cfg(sink: &CovexpSink) -> FunctionCfg {
        let conn = sink.conn();
        let covered = query::group_coverage_bitmap(conn, None).unwrap();
        let frontier = covexp_core::coverage::compute_frontier(conn, &covered).unwrap();
        let func = query::list_functions(conn)
            .unwrap()
            .into_iter()
            .find(|f| f.name == "harness")
            .unwrap();
        query::function_cfg(conn, func.id, &covered, &frontier).unwrap()
    }

    #[test]
    fn test_covexp_if_arms_are_distinct_edges() {
        for body in [
            "local.get 1 if nop else nop end nop",
            "local.get 1 if nop end nop",
        ] {
            let mod_spec = wat_harness(body);
            for input in [&b""[..], b"x"] {
                let cfg = harness_cfg(&import_runs(&mod_spec, &[input]));
                let frontier = cfg.edges.iter().filter(|e| e.is_frontier).count();
                assert_eq!(frontier, 1, "`{body}` on {input:?}: {cfg:#?}");
            }
            let cfg = harness_cfg(&import_runs(&mod_spec, &[b"", b"x"]));
            assert!(
                cfg.edges.iter().all(|e| e.covered),
                "`{body}`, both arms taken: {cfg:#?}"
            );
        }
    }

    /// Every edge the edge pass has a key for is one the JIT can emit: drive
    /// each kind of branch both ways and nothing may be left over.
    #[test]
    fn test_covexp_every_instrumented_edge_is_emitted() {
        let mod_spec = wat_harness(
            r#"
            block $exit
              block $b2
                block $b1
                  block $b0
                    local.get 1
                    br_table $b0 $b1 $b2 $b0 $b0 $exit
                  end
                  local.get 1
                  i32.const 3
                  i32.eq
                  if nop else nop end
                  br $exit
                end
                i32.const 2
                local.set 1
                loop $l
                  local.get 1
                  i32.const 1
                  i32.sub
                  local.tee 1
                  br_if $l
                end
                br $exit
              end
              local.get 0
              i32.load8_u
              if nop end
            end"#,
        );
        let inputs: [&[u8]; 7] = [b"", b"", b"  ", b" ", b"   ", b"    ", b"     "];
        let harness = mod_spec
            .functions
            .iter()
            .find(|f| f._symbol.as_deref() == Some("harness"))
            .unwrap()
            .idx;

        let mut stats = Stats::default();
        let mut sess = coverage_session(mod_spec.clone(), &mut stats);
        for input in inputs {
            let _ = sess.run(input, &mut stats);
        }
        let edges = &sess.get_pass::<EdgeCoveragePass>().coverage;
        let never_emitted = edges
            .keys
            .iter()
            .zip(edges.saved.iter())
            .filter(|(key, covered)| key.function == harness && !**covered)
            .map(|(key, _)| key)
            .collect::<Vec<_>>();
        assert!(never_emitted.is_empty(), "never emitted: {never_emitted:?}");

        let cfg = harness_cfg(&import_runs(&mod_spec, &inputs));
        assert!(cfg.edges.iter().all(|e| e.covered), "{cfg:#?}");
    }

    #[test]
    fn test_covexp_code_after_a_trap_is_not_covered() {
        // Blocks: [block, local.get, br_if] [unreachable] [nop, end] [nop, end]
        // The third only follows the trap: it's dead, and has no edges.
        let mod_spec = wat_harness("block local.get 1 br_if 0 unreachable nop end nop");
        let cfg = harness_cfg(&import_runs(&mod_spec, &[b""]));
        assert_eq!(cfg.blocks.len(), 4, "{cfg:#?}");
        let dead = cfg.blocks[2].id;
        assert!(
            cfg.edges
                .iter()
                .all(|e| e.from_block != dead && e.to_block != dead),
            "{cfg:#?}"
        );
        assert!(!cfg.blocks[3].covered, "{cfg:#?}");

        let cfg = harness_cfg(&import_runs(&mod_spec, &[b"", b"x"]));
        assert!(cfg.edges.iter().all(|e| e.covered), "{cfg:#?}");
    }

    #[test]
    fn test_covexp_branch_into_end_marks_its_block() {
        // `br_if 0` jumps straight to the outer `end`, which starts a basic
        // block of its own. Taking it must mark that block, or the edge out of
        // it (implied by both endpoints having run) is never covered.
        let mod_spec = wat_harness("block block local.get 1 br_if 0 nop end end nop");
        let cfg = harness_cfg(&import_runs(&mod_spec, &[b"x"]));
        let frontier = cfg.edges.iter().filter(|e| e.is_frontier).count();
        assert_eq!(frontier, 1, "only the untaken fallthrough: {cfg:#?}");
        let uncovered = cfg.edges.iter().filter(|e| !e.covered).count();
        assert_eq!(
            uncovered, 2,
            "the untaken fallthrough and what follows it: {cfg:#?}"
        );
    }

    #[test]
    fn test_covexp_calls_are_attributed_to_their_instruction() {
        // The last call shares a basic block with a call that traps. It never
        // runs, although its basic block is entered and its callee is entered
        // from the first call.
        let mod_spec = wat_harness("call $callee local.get 1 if call $trap call $callee end");
        let cfg = harness_cfg(&import_runs(&mod_spec, &[b"x"]));
        let calls = cfg
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::DirectCall)
            .map(|e| (e.to_block, e.covered))
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 3, "{cfg:#?}");
        assert_eq!(
            calls
                .iter()
                .map(|(_, covered)| *covered)
                .collect::<Vec<_>>(),
            [true, true, false],
            "{cfg:#?}"
        );
        assert_eq!(calls[0].0, calls[2].0, "both calls go to $callee");

        // Behind an `unreachable` instead, the call is dead code and isn't
        // part of the graph at all.
        let mod_spec = wat_harness("call $callee local.get 1 if unreachable call $callee end");
        let cfg = harness_cfg(&import_runs(&mod_spec, &[b"x"]));
        let calls = cfg.edges.iter().filter(|e| e.kind == EdgeKind::DirectCall);
        assert_eq!(calls.count(), 1, "{cfg:#?}");

        // A call that doesn't return reaches its callee, but not what follows.
        let mod_spec = wat_harness("call $trap nop");
        let cfg = harness_cfg(&import_runs(&mod_spec, &[b""]));
        let (before, after) = (cfg.blocks[0].id, cfg.blocks[1].id);
        assert!(cfg.blocks[0].covered && !cfg.blocks[1].covered, "{cfg:#?}");
        let edge = |from, kind| {
            cfg.edges
                .iter()
                .find(|e| e.from_block == from && e.kind == kind)
                .unwrap()
        };
        assert!(edge(before, EdgeKind::DirectCall).covered, "{cfg:#?}");
        assert!(!edge(before, EdgeKind::Fallthrough).covered, "{cfg:#?}");
        assert_eq!(edge(before, EdgeKind::Fallthrough).to_block, after);
    }

    #[test]
    fn test_covexp_inputs_dont_see_earlier_inputs_state() {
        // Only a second run in the same instance would find the flag set.
        let mod_spec =
            wat_harness("global.get $flag if call $callee end i32.const 1 global.set $flag");
        let sink = import_runs(&mod_spec, &[b"a", b"b"]);
        let tcs = query::list_testcases(sink.conn()).unwrap();
        let bitmaps = tcs
            .iter()
            .map(|tc| query::testcase_coverage_bitmap(sink.conn(), tc.id).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(bitmaps[0], bitmaps[1]);
        let cfg = harness_cfg(&sink);
        assert!(
            cfg.edges
                .iter()
                .filter(|e| e.kind == EdgeKind::DirectCall)
                .all(|e| !e.covered),
            "{cfg:#?}"
        );
    }

    #[test]
    fn test_covexp_last_run_is_just_that_run() {
        let mod_spec = wat_harness("local.get 1 if call $callee end");
        let mut stats = Stats::default();
        let mut sess = coverage_session(mod_spec.clone(), &mut stats);
        let mut sink = CovexpSink::attach(
            schema::open_in_memory().unwrap(),
            &mod_spec,
            "test",
            None,
            None,
        );
        let _ = sess.run(b"x", &mut stats);
        sess.reset_pass_coverage_keep_saved();
        let _ = sess.run(b"", &mut stats);
        sink.add_testcase(&sess, Observed::LastRun, None, None);
        sink.add_testcase(&sess, Observed::Accumulated, None, None);

        let tcs = query::list_testcases(sink.conn()).unwrap();
        let last = query::testcase_coverage_bitmap(sink.conn(), tcs[0].id).unwrap();
        let all = query::testcase_coverage_bitmap(sink.conn(), tcs[1].id).unwrap();
        assert!(last.is_subset(&all) && last != all);
        let alone = import_runs(&mod_spec, &[b""]);
        let alone_tc = query::list_testcases(alone.conn()).unwrap()[0].id;
        assert_eq!(
            last,
            query::testcase_coverage_bitmap(alone.conn(), alone_tc).unwrap()
        );
    }

    #[test]
    fn test_covexp_open_appends_groups_but_refuses_other_modules() {
        let db =
            std::env::temp_dir().join(format!("wasmfuzz-covexp-open-{}.db", std::process::id()));
        let remove = || {
            for suffix in ["", "-wal", "-shm"] {
                let mut path = db.clone().into_os_string();
                path.push(suffix);
                let _ = std::fs::remove_file(path);
            }
        };
        remove();
        let mod_spec = wat_harness("nop");
        let function_count = {
            let sink = CovexpSink::open(&db, &mod_spec, "a", None, None, false, false).unwrap();
            query::list_functions(sink.conn()).unwrap().len()
        };
        // The same module again: a second group over the structure that's there.
        {
            let mut stats = Stats::default();
            let mut sess = coverage_session(mod_spec.clone(), &mut stats);
            sess.reset_pass_coverage();
            let _ = sess.run(b"", &mut stats);
            let mut sink = CovexpSink::open(&db, &mod_spec, "b", None, None, false, false).unwrap();
            sink.add_testcase(&sess, Observed::Accumulated, Some("b0"), None);
            assert_eq!(
                query::list_functions(sink.conn()).unwrap().len(),
                function_count
            );
            let groups = query::list_groups(sink.conn()).unwrap();
            assert_eq!(groups.len(), 2, "{groups:?}");
            let b = groups.iter().find(|group| group.name == "b").unwrap();
            let covered = query::group_coverage_bitmap(sink.conn(), Some(b.id)).unwrap();
            assert!(!covered.is_empty());
            // The appended bitmap speaks the first import's edge IDs.
            let fresh = import_runs(&mod_spec, &[b""]);
            let fresh_tc = query::list_testcases(fresh.conn()).unwrap()[0].id;
            assert_eq!(
                covered,
                query::testcase_coverage_bitmap(fresh.conn(), fresh_tc).unwrap()
            );
        }
        // A group that's already there only takes more testcases when asked to.
        assert!(CovexpSink::open(&db, &mod_spec, "b", None, None, false, false).is_err());
        {
            let sink = CovexpSink::open(&db, &mod_spec, "b", None, None, false, true).unwrap();
            assert_eq!(query::list_groups(sink.conn()).unwrap().len(), 2);
        }
        // Another module's edge IDs would mean nothing here.
        let other = wat_harness("local.get 1 if call $callee end");
        assert!(CovexpSink::open(&db, &other, "c", None, None, false, false).is_err());
        assert!(CovexpSink::open(&db, &other, "c", None, None, false, true).is_err());
        let sink = CovexpSink::open(&db, &other, "c", None, None, true, false).unwrap();
        let groups = query::list_groups(sink.conn()).unwrap();
        assert_eq!(groups.len(), 1, "{groups:?}");
        drop(sink);
        remove();
    }

    fn compile_wasm(code: &str) -> Vec<u8> {
        static FS_LOCK: Mutex<()> = Mutex::new(());
        let _guard = FS_LOCK.lock().unwrap();
        let id = format!("{:x}", md5::compute(code.as_bytes()));
        let code_path = format!("/tmp/wasmfuzz-covexp-test-{id}.rs");
        let mod_path = format!("/tmp/wasmfuzz-covexp-test-{id}.wasm");
        if let Ok(bin) = std::fs::read(&mod_path) {
            return bin;
        }
        std::fs::write(&code_path, code).unwrap();
        let status = std::process::Command::new("rustc")
            .arg("--crate-type=cdylib")
            .arg("--target=wasm32-wasip1")
            .arg("--edition=2021")
            .args(["-C", "codegen-units=1"])
            .args(["-C", "link-dead-code=no"])
            .arg("-g")
            .arg(&code_path)
            .arg("-o")
            .arg(&mod_path)
            .status()
            .expect("failed to invoke rustc");
        assert!(status.success(), "rustc failed");
        std::fs::read(&mod_path).unwrap()
    }

    #[test]
    fn test_covexp_import_roundtrip() {
        let code = r#"
#[unsafe(no_mangle)]
pub extern "C" fn wasmfuzz_malloc(size: usize) -> *mut u8 {
    unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(size, 8)) }
}
#[unsafe(no_mangle)]
pub extern "C" fn LLVMFuzzerTestOneInput(buf: *const u8, len: usize) {
    let data = unsafe { std::slice::from_raw_parts(buf, len) };
    if data.len() == 4 {
        if data[0] == 1 {
            if data[1] == 2 {
                if data[2] == 3 {
                    if data[3] == 4 {
                        panic!()
                    }
                }
            }
        }
    }
    let found = data.len() == 4
        && data[0] == 1
        && data[1] == 2
        && data[2] == 3
        && data[3] == 4;
    if found {
        panic!()
    }
}
"#;
        let wasm = compile_wasm(code);
        let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &wasm).unwrap());

        let mut stats = Stats::default();
        let mut sess = coverage_session(mod_spec.clone(), &mut stats);

        let mut sink = CovexpSink::attach(
            schema::open_in_memory().unwrap(),
            &mod_spec,
            "wasmfuzz-test",
            None,
            None,
        );
        for (i, inp) in [b"AAAA", b"\x01AAA", b"\x01\x02AA"].iter().enumerate() {
            sess.reset_pass_coverage();
            let _ = sess.run(inp.as_slice(), &mut stats);
            sink.add_testcase(
                &sess,
                Observed::Accumulated,
                Some(format!("tc-{i}").as_str()),
                Some(inp.as_slice()),
            );
        }
        let conn = sink.conn();

        let empty = RoaringBitmap::new();
        let funcs = query::list_functions(conn).unwrap();
        let fn_count = funcs.len();
        assert!(fn_count > 0, "no functions imported");

        let target_fn_count = funcs
            .iter()
            .filter(|f| {
                f.name.contains("LLVMFuzzerTestOneInput")
                    || f.demangled_name
                        .as_deref()
                        .is_some_and(|n| n.contains("LLVMFuzzerTestOneInput"))
            })
            .count();
        assert!(target_fn_count >= 1, "LLVMFuzzerTestOneInput not imported");

        let mut block_count = 0usize;
        let mut edge_count = 0usize;
        let mut max_edge_id = 0i64;
        let mut call_edges = 0usize;
        let mut self_loops = 0usize;
        for func in &funcs {
            let cfg = query::function_cfg(conn, func.id, &empty, &empty).unwrap();
            block_count += cfg.blocks.len();
            edge_count += cfg.edges.len();
            for e in &cfg.edges {
                max_edge_id = max_edge_id.max(e.id);
                if e.kind == EdgeKind::DirectCall {
                    call_edges += 1;
                }
                if e.from_block == e.to_block {
                    self_loops += 1;
                }
            }
        }
        assert!(block_count >= fn_count, "fewer blocks than functions");

        assert!(edge_count > 0, "no edges imported");
        // The frontier can only leave a function along a call edge.
        assert!(call_edges > 0, "no call edges imported");
        // Self-loops are markers for blocks whose coverage no real edge can
        // express — one per function entry, plus the odd unreachable block.
        assert!(
            self_loops <= fn_count + fn_count / 2,
            "{self_loops} block markers for {fn_count} functions: expected roughly one per function",
        );

        let tcs = query::list_testcases(conn).unwrap();
        // One testcase per input, each with the input that produced it.
        assert_eq!(tcs.len(), 3, "expected one testcase per input");
        for tc in &tcs {
            assert!(
                query::testcase_input(conn, tc.id).unwrap().is_some(),
                "testcase {} has no stored input",
                tc.id,
            );
        }
        let file_count = query::list_files(conn).unwrap().len();
        assert!(file_count > 0, "no source files imported");

        let harness_path = query::list_files(conn)
            .unwrap()
            .into_iter()
            .map(|f| f.path)
            .find(|p| p.contains("wasmfuzz-covexp-test"))
            .expect("expected rustc temp test source path in DWARF");
        let annotated =
            query::annotated_source_for_file_path(conn, &harness_path, Some(tcs[0].group_id))
                .expect("annotated source for harness file");
        assert!(
            annotated.contains("LLVMFuzzerTestOneInput"),
            "annotated output should include fuzzer symbol: {annotated:?}",
        );

        // Per-line testcase counts: each nested `if` is reached by one fewer of
        // the three inputs. The gutter below can't show these on lines that are
        // also on the frontier, so check them at the source.
        let harness_id = query::list_files(conn)
            .unwrap()
            .into_iter()
            .find(|f| f.path == harness_path)
            .unwrap()
            .id;
        let harness_file = query::get_file(conn, harness_id).unwrap();
        let counts = query::file_line_hit_counts(conn, harness_file.id, Some(tcs[0].group_id))
            .expect("hit counts for harness file");
        let count_for = |needle: &str| {
            let line = harness_file
                .content
                .lines()
                .position(|l| l.contains(needle))
                .expect("line not found");
            counts[line]
        };
        assert_eq!(count_for("if data[0] == 1 {"), 3);
        assert_eq!(count_for("if data[1] == 2 {"), 2);
        assert_eq!(count_for("if data[2] == 3 {"), 1);
        assert_eq!(count_for("if data[3] == 4 {"), 0);

        // Strip lines before LLVMFuzzerTestOneInput
        let annotated = annotated
            .lines()
            .skip_while(|l| !l.contains("LLVMFuzzerTestOneInput"))
            .collect::<Vec<_>>()
            .join("\n");
        // Note: Keep the structure as-is, don't simplify to "make the test less brittle".
        // Gutter: `[N]` = N testcases hit the line (0-9), `[+]` = >9, `[!]` = frontier,
        // three spaces = no instrumented edge. Every `if` here has an untaken
        // branch, so it renders `[!]` and its testcase count is not shown — the
        // counts are asserted above instead.
        let expected = r#"
[3] | pub extern "C" fn LLVMFuzzerTestOneInput(buf: *const u8, len: usize) {
[3] |     let data = unsafe { std::slice::from_raw_parts(buf, len) };
[!] |     if data.len() == 4 {
[!] |         if data[0] == 1 {
[!] |             if data[1] == 2 {
[!] |                 if data[2] == 3 {
[0] |                     if data[3] == 4 {
[0] |                         panic!()
    |                     }
    |                 }
    |             }
    |         }
    |     }
[!] |     let found = data.len() == 4
[!] |         && data[0] == 1
[!] |         && data[1] == 2
[!] |         && data[2] == 3
[0] |         && data[3] == 4;
[!] |     if found {
[0] |         panic!()
    |     }
[3] | }
"#;
        let expected = &expected[1..expected.len() - 1];
        if expected != annotated {
            eprintln!("expected: {expected}");
            eprintln!("actual: {annotated}");
        }
        assert_eq!(annotated, expected);
    }
}
