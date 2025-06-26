// TODO(dwarf): accuracy for this kind of sucks. is there a better way?
//              this suggest that high line coverage accuracy should be possible for -O0 (fig 10):
//              https://arxiv.org/abs/2402.04811v1

use crate::HashMap;
use crate::instrumentation::BBCoveragePass;
use std::path::PathBuf;
use std::sync::Arc;

use bitvec::vec::BitVec;
use clap::Parser;

use symbolic::common::ByteView;
use symbolic::debuginfo::{Function, Object};

use crate::ir::Location;
use crate::ir::ModuleSpec;
use crate::jit::{FeedbackOptions, JitFuzzingSession};

#[derive(Debug, Default, Clone)]
pub(crate) struct FileLineCoverage {
    pub instrumented: BitVec,
    pub covered: BitVec,
    // cover_count: Vec<u16>,
}

impl FileLineCoverage {
    pub fn set_covered(&mut self, line: usize) {
        if line == 0 {
            return;
        }
        if self.covered.len() <= line {
            self.covered.resize(line + 1, false);
        }
        self.covered.set(line, true);
    }
    pub fn set_instrumented(&mut self, line: usize) {
        if line == 0 {
            return;
        }
        if self.instrumented.len() <= line {
            self.instrumented.resize(line + 1, false);
        }
        self.instrumented.set(line, true);
    }
}

#[derive(Parser)]
pub(crate) struct LcovOpts {
    pub program: PathBuf,
    #[clap(long)]
    pub seed_files: Vec<String>,
    #[clap(long)]
    pub dir: Option<String>,
    #[clap(short, long)]
    output: Option<String>,
}

fn resolve_(function: &Function<'_>, addr: u64, covered: &mut HashMap<String, FileLineCoverage>) {
    if function.address > addr || function.address + function.size <= addr {
        return;
    }

    for il in &function.inlinees {
        resolve_(il, addr, covered);
    }

    for line in &function.lines {
        if line.address + line.size.unwrap_or(1) <= addr {
            continue;
        } else if line.address > addr {
            break;
        }
        if line.line == 0 {
            continue;
        }

        covered
            .entry(line.file.path_str())
            .or_default()
            .set_covered(line.line as usize - 1);
        break;
    }
}

fn resolve_instrumented(
    function: &Function<'_>,
    instrumented: &mut HashMap<String, FileLineCoverage>,
) {
    for il in &function.inlinees {
        resolve_instrumented(il, instrumented);
    }

    for line in &function.lines {
        if line.line != 0 {
            let file = line.file.path_str();
            instrumented
                .entry(file)
                .or_default()
                .set_instrumented(line.line as usize - 1);
        }
    }
}

pub(crate) fn process_file_line_coverage(
    mod_spec: &ModuleSpec,
    sess: &JitFuzzingSession,
) -> HashMap<String, FileLineCoverage> {
    let view = ByteView::from_slice(&mod_spec.wasm_binary);
    let object = Object::parse(&view).expect("failed to parse file");
    assert!(object.has_debug_info());
    let session = object.debug_session().expect("failed to process file");

    let mut covered_offsets = Vec::new();
    for func in &mod_spec.functions {
        let base = func.operators_wasm_bin_offset_base;
        let mut loc = Location {
            function: func.idx,
            index: 0,
        };
        let mut addrs = Vec::new();
        for (i, &off_rel) in func.operator_offset_rel.iter().enumerate() {
            loc.index = func.operator_basic_block[i].0;
            if sess.get_pass::<BBCoveragePass>().coverage.saved_val(&loc) {
                let addr = base + off_rel as usize;
                addrs.push(addr);
            }
        }
        if !addrs.is_empty() {
            covered_offsets.push(addrs);
        }
    }

    let mut covered = HashMap::default();

    for function in session.functions() {
        let function = function.expect("failed to read function");
        for addrs in &covered_offsets {
            let start = addrs[0] as u64;
            let end = addrs[addrs.len() - 1] as u64;
            if function.address >= end || start >= function.address + function.size {
                continue;
            }

            for &addr in addrs {
                resolve_(&function, addr as u64, &mut covered);
            }
        }
    }

    for function in session.functions() {
        let function = function.expect("failed to read function");
        resolve_instrumented(&function, &mut covered);
    }

    covered
}

pub(crate) fn run(mod_spec: Arc<ModuleSpec>, input_paths: &[PathBuf], opts: &LcovOpts) {
    let mut stats = crate::jit::Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec.clone())
        .feedback(FeedbackOptions {
            live_funcs: true,
            live_bbs: true,
            ..FeedbackOptions::nothing()
        })
        .build();
    sess.initialize(&mut stats);

    for path in input_paths {
        // dbg!(&path);
        let input = std::fs::read(path).unwrap();
        assert!(input.len() <= crate::TEST_CASE_SIZE_LIMIT);
        let _res = sess.run(&input, &mut stats);
    }

    let covered = process_file_line_coverage(&mod_spec, &sess);

    let mut lcov_records = Vec::new();
    let mut covered: Vec<_> = covered.into_iter().collect();
    covered.sort_by_cached_key(|(key, _)| (!key.starts_with('/'), key.clone()));
    for (path, coverage) in covered {
        lcov_records.push(lcov::Record::TestName {
            name: String::new(),
        });
        lcov_records.push(lcov::Record::SourceFile {
            path: PathBuf::from(&path),
        });
        lcov_records.push(lcov::Record::LinesFound {
            found: coverage.instrumented.count_ones() as u32,
        });
        lcov_records.push(lcov::Record::LinesHit {
            hit: coverage.covered.count_ones() as u32,
        });
        for line in coverage.instrumented.iter_ones() {
            let covered = coverage
                .covered
                .get(line)
                .as_deref()
                .copied()
                .unwrap_or(false);
            if covered {
                println!("{path}:{line} [x]");
            } else {
                println!("{path}:{line}  -");
            }
            lcov_records.push(lcov::Record::LineData {
                line: line as u32,
                count: covered as u64,
                checksum: None,
            });
        }
        lcov_records.push(lcov::Record::EndOfRecord);
    }

    if let Some(path) = &opts.output {
        use std::fmt::Write;
        let contents = lcov_records
            .into_iter()
            .fold(String::new(), |mut output, rec| {
                let _ = writeln!(output, "{rec}");
                output
            });

        std::fs::write(path, contents).unwrap();
    }
}
