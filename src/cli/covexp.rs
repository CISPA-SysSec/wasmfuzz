use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use covexp_core::import::{FileId, Importer, SourceLoc};
use covexp_core::model::EdgeKind;
use covexp_core::rusqlite::Connection;
use symbolic::debuginfo::Object;

use crate::HashMap;
use crate::instrumentation::{Edge, EdgeCoveragePass, FuncIdx, FunctionCoveragePass};
use crate::ir::{InsnIdx, ModuleSpec, debuginfo_helper::resolve_source_location};
use crate::jit::JitFuzzingSession;

#[derive(Parser)]
pub(crate) struct CovexpImportOpts {
    pub program: PathBuf,
    #[clap(long)]
    pub seed_files: Vec<String>,
    #[clap(long)]
    pub dir: Option<String>,
    #[clap(long, default_value = "covexp.db")]
    pub db: PathBuf,
    #[clap(long, default_value = "wasmfuzz")]
    pub group: String,
    #[clap(long)]
    pub testcase_label: Option<String>,
    #[clap(long)]
    pub source_root: Option<PathBuf>,
    #[clap(long)]
    pub strip_prefix: Option<String>,
}

fn import_coverage(
    mod_spec: &ModuleSpec,
    sess: &JitFuzzingSession,
    db: &Path,
    group: &str,
    testcase_label: Option<&str>,
    source_root: Option<&Path>,
    strip_prefix: Option<&str>,
) {
    let conn = covexp_core::schema::open(db.to_string_lossy().as_ref()).unwrap();
    import_coverage_into(
        &conn,
        mod_spec,
        sess,
        group,
        testcase_label,
        source_root,
        strip_prefix,
    );
}

pub(crate) fn import_coverage_into(
    conn: &Connection,
    mod_spec: &ModuleSpec,
    sess: &JitFuzzingSession,
    group: &str,
    testcase_label: Option<&str>,
    source_root: Option<&Path>,
    strip_prefix: Option<&str>,
) {
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

    let mut covered_edges = Vec::new();
    let covered_cfg_edges = sess
        .get_pass::<EdgeCoveragePass>()
        .coverage
        .iter_covered_keys()
        .collect::<std::collections::BTreeSet<_>>();
    let covered_funcs = sess
        .get_pass::<FunctionCoveragePass>()
        .coverage
        .iter_covered_keys()
        .collect::<std::collections::BTreeSet<_>>();

    for func in &mod_spec.functions {
        let func_name = func._symbol.as_deref().unwrap_or(func.symbol.as_str());
        let mut block_ids = HashMap::<InsnIdx, covexp_core::import::BlockId>::default();
        let mut ordered_blocks = func.basic_block_starts.clone();
        ordered_blocks.sort();

        let mut first_file = None;
        let mut start_line = None;
        let mut end_line = None;
        let mut block_locations = Vec::new();
        for (block_idx, bb_start) in ordered_blocks.iter().enumerate() {
            let mut locs = Vec::<(String, u32, Option<u32>)>::new();
            let block_start = bb_start.i();
            let block_end = ordered_blocks
                .get(block_idx + 1)
                .map(|next| next.i())
                .unwrap_or(func.operator_offset_rel.len())
                .min(func.operator_offset_rel.len());
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
            for (path, line, _) in locs {
                let file_id = if let Some(id) = file_ids.get(path) {
                    *id
                } else {
                    let content = read_source(path, source_root);
                    let id = imp.add_source_file(path, content.as_str()).unwrap();
                    file_ids.insert(path.clone(), id);
                    id
                };
                if first_file.is_none() {
                    first_file = Some(file_id);
                }
                start_line = Some(start_line.map_or(*line, |x: u32| x.min(*line)));
                end_line = Some(end_line.map_or(*line, |x: u32| x.max(*line)));
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
            block_ids.insert(bb_start, block);
        }

        let mut next_bb = HashMap::<InsnIdx, InsnIdx>::default();
        for pair in ordered_blocks.windows(2) {
            next_bb.insert(pair[0], pair[1]);
        }

        let mut covered_blocks = std::collections::BTreeSet::<InsnIdx>::new();
        if covered_funcs.contains(&FuncIdx(func.idx))
            && let Some(entry) = ordered_blocks.first()
        {
            covered_blocks.insert(*entry);
        }

        for &(from, to) in &func.critical_insn_edges {
            let Some(&from_block) = block_ids.get(&from) else {
                continue;
            };
            let Some(&to_block) = block_ids.get(&to) else {
                continue;
            };
            let kind = if next_bb.get(&from) == Some(&to) {
                EdgeKind::Fallthrough
            } else {
                EdgeKind::Branch
            };
            let edge_id = imp.add_edge(from_block, to_block, kind).unwrap();
            if covered_cfg_edges.contains(&Edge::new(func.idx, from, to)) {
                covered_blocks.insert(from);
                covered_blocks.insert(to);
                covered_edges.push(edge_id);
            }
        }

        // Save per-block synthetic edges so line rendering can mark uncovered
        // instrumented blocks as `[ ]` even when they have no critical edge.
        for bb_start in &ordered_blocks {
            let Some(&block_id) = block_ids.get(bb_start) else {
                continue;
            };
            let edge_id = imp
                .add_edge(block_id, block_id, EdgeKind::Fallthrough)
                .unwrap();
            if covered_blocks.contains(bb_start) {
                covered_edges.push(edge_id);
            }
        }
    }

    let group_id = imp.add_group(group).unwrap();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    imp.add_testcase(
        group_id,
        testcase_label,
        Some(timestamp),
        covered_edges.as_slice(),
    )
    .unwrap();
    tx.commit().unwrap();
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

pub(crate) fn import_snapshot(
    mod_spec: Arc<ModuleSpec>,
    sess: &JitFuzzingSession,
    db: &Path,
    group: &str,
    testcase_label: Option<&str>,
) {
    import_coverage(
        mod_spec.as_ref(),
        sess,
        db,
        group,
        testcase_label,
        None,
        None,
    );
}

pub(crate) fn run(mod_spec: Arc<ModuleSpec>, input_paths: &[PathBuf], opts: &CovexpImportOpts) {
    let sess = super::lcov::run_inputs(mod_spec.clone(), input_paths);
    let default_label = opts.program.to_string_lossy().into_owned();
    let testcase_label = opts.testcase_label.clone().unwrap_or(default_label);
    import_coverage(
        &mod_spec,
        &sess,
        &opts.db,
        &opts.group,
        Some(&testcase_label),
        opts.source_root.as_deref(),
        opts.strip_prefix.as_deref(),
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use covexp_core::query;
    use covexp_core::roaring::RoaringBitmap;
    use covexp_core::schema;

    use super::*;
    use crate::jit::{FeedbackOptions, Stats};

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
        let mut sess = JitFuzzingSession::builder(mod_spec.clone())
            .feedback(FeedbackOptions {
                live_funcs: true,
                live_bbs: true,
                live_edges: true,
                ..FeedbackOptions::nothing()
            })
            .build();
        sess.initialize(&mut stats);

        let conn = schema::open_in_memory().unwrap();
        for (i, inp) in [b"AAAA", b"\x01AAA", b"\x01\x02AA"].iter().enumerate() {
            sess.reset_pass_coverage();
            let _ = sess.run(inp.as_slice(), &mut stats);
            import_coverage_into(
                &conn,
                &mod_spec,
                &sess,
                "wasmfuzz-test",
                Some(format!("tc-{i}").as_str()),
                None,
                None,
            );
        }

        let empty = RoaringBitmap::new();
        let funcs = query::list_functions(&conn).unwrap();
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
        for func in &funcs {
            let cfg = query::function_cfg(&conn, func.id, &empty, &empty).unwrap();
            block_count += cfg.blocks.len();
            edge_count += cfg.edges.len();
            for e in &cfg.edges {
                max_edge_id = max_edge_id.max(e.id);
            }
        }
        assert!(block_count >= fn_count, "fewer blocks than functions");

        assert!(edge_count > 0, "no edges imported");

        let tcs = query::list_testcases(&conn).unwrap();
        let file_count = query::list_files(&conn).unwrap().len();
        assert!(file_count > 0, "no source files imported");

        let harness_path = query::list_files(&conn)
            .unwrap()
            .into_iter()
            .map(|f| f.path)
            .find(|p| p.contains("wasmfuzz-covexp-test"))
            .expect("expected rustc temp test source path in DWARF");
        let annotated =
            query::annotated_source_for_file_path(&conn, &harness_path, Some(tcs[0].group_id))
                .expect("annotated source for harness file");
        assert!(
            annotated.contains("LLVMFuzzerTestOneInput"),
            "annotated output should include fuzzer symbol: {annotated:?}",
        );

        // Strip lines before LLVMFuzzerTestOneInput
        let annotated = annotated
            .lines()
            .skip_while(|l| !l.contains("LLVMFuzzerTestOneInput"))
            .collect::<Vec<_>>()
            .join("\n");
        // Note: Keep the structure as-is, don't simplify to "make the test less brittle".
        // Gutter: `[N]` = N testcases hit the line (0-9), `[+]` = >9, `[!]` = frontier,
        // three spaces = no instrumented edge. Single testcase here, so covered lines show `[1]`.
        let expected = r#"
[3] | pub extern "C" fn LLVMFuzzerTestOneInput(buf: *const u8, len: usize) {
[3] |     let data = unsafe { std::slice::from_raw_parts(buf, len) };
[3] |     let found = data.len() == 4
[1] |         && data[0] == 1
[1] |         && data[1] == 2
[1] |         && data[2] == 3
[0] |         && data[3] == 4;
[0] |     if found {
[0] |         panic!()
    |     }
[0] | }
"#;
        let expected = &expected[1..expected.len() - 1];
        if expected != annotated {
            eprintln!("expected: {expected}");
            eprintln!("actual: {annotated}");
        }
        assert_eq!(annotated, expected);
    }
}
