use crate::instrumentation::BBCoveragePass;
use crate::ir::debuginfo_helper::resolve_source_location;
use crate::HashMap;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use askama::Template;
use symbolic::debuginfo::{Object, ObjectError};
use syntect::highlighting::ThemeSet;
use syntect::html::{css_for_theme_with_class_style, ClassStyle};
use syntect::parsing::{
    BasicScopeStackOp, ParseState, Scope, ScopeRepository, ScopeStack, SyntaxReference, SyntaxSet,
    SCOPE_REPO,
};
use syntect::util::LinesWithEndings;

use crate::ir::{Location, ModuleSpec};
use crate::jit::{FeedbackOptions, JitFuzzingSession};

use super::lcov::FileLineCoverage;

#[derive(Default, Clone)]
struct Counters {
    n_statements: usize,
    n_executed: usize,
    n_missing: usize,
    n_excluded: usize,
    n_branches: usize,
    n_executed_branches: usize,
    n_partial_branches: usize,
}

impl Counters {
    fn coverage_ratio(&self) -> (usize, usize) {
        (
            self.n_executed + self.n_executed_branches,
            self.n_statements + self.n_branches,
        )
    }
    fn coverage_percent(&self) -> String {
        let (num, denom) = self.coverage_ratio();
        let ratio = num as f32 / denom as f32;
        format!("{}%", (ratio * 100.0).round())
    }

    fn add(self, other: &Self) -> Self {
        Self {
            n_statements: self.n_statements + other.n_statements,
            n_executed: self.n_executed + other.n_executed,
            n_missing: self.n_missing + other.n_missing,
            n_excluded: self.n_excluded + other.n_excluded,
            n_branches: self.n_branches + other.n_branches,
            n_executed_branches: self.n_executed_branches + other.n_executed_branches,
            n_partial_branches: self.n_partial_branches + other.n_partial_branches,
        }
    }
}

struct IndexFile {
    nums: Counters,
    relative_filename: String,
    html_filename: String,
    coverage: FileLineCoverage,
    is_stdlib: bool,
}

struct FileLine<'a> {
    number: usize,
    html: String,
    annotate: Option<(String, String)>,
    contexts: bool,
    context_list: bool,
    context_str: &'a str,
    contexts_label: &'a str,
    css_class: &'a str,
}

#[derive(Template)]
#[template(path = "index.html", whitespace = "suppress")]
struct IndexTemplate<'a> {
    harness_name: &'a str,
    totals: Counters,
    files: &'a [IndexFile],
}

#[derive(Template)]
#[template(path = "file.html", whitespace = "suppress")]
struct FileTemplate<'a> {
    relative_filename: &'a str,
    prev_html: &'a str,
    next_html: &'a str,
    nums: Counters,
    missing_source: bool,
    lines: &'a [FileLine<'a>],
}

#[derive(Parser)]
pub(crate) struct HtmlCovOpts {
    pub program: PathBuf,
    #[clap(long)]
    pub seed_files: Vec<String>,
    #[clap(long)]
    pub corpus: Option<String>,
    #[clap(short, long)]
    output: String,
}

fn run_inputs(mod_spec: Arc<ModuleSpec>, input_paths: &[PathBuf]) -> JitFuzzingSession {
    let mut stats = crate::jit::Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(FeedbackOptions {
            live_funcs: true,
            live_bbs: true,
            live_edges: true,
            ..FeedbackOptions::nothing()
        })
        .build();
    sess.initialize(&mut stats);

    for path in input_paths {
        eprint!("{path:?}\r");
        let input = std::fs::read(path).unwrap();
        if input.len() > crate::TEST_CASE_SIZE_LIMIT {
            println!("skipping testcase {path:?} due to size limit");
            continue;
        }
        let _res = sess.run(&input, &mut stats);
    }
    eprint!("{}\r", " ".repeat(120));

    sess
}

#[derive(Debug, Copy, Clone)]
struct FileId(u32);

struct FileInfo {
    path: String,
    source: Option<String>,
    line_coverage: FileLineCoverage,
}

pub(crate) struct ReportInfo {
    mod_spec: Arc<ModuleSpec>,
    files: Vec<FileInfo>,
    path_to_fileid: HashMap<String, FileId>,
}

impl ReportInfo {
    pub(crate) fn new(mod_spec: Arc<ModuleSpec>) -> Result<Self, ObjectError> {
        let object = Object::parse(&mod_spec.wasm_binary).expect("failed to parse file");
        assert!(object.has_debug_info());
        assert!(object.has_sources());
        let debug_session = object.debug_session().expect("failed to process file");

        let mut files = debug_session.files().collect::<Result<Vec<_>, _>>()?;
        // make sure we keep the copies that contain source code information
        files.sort_by_key(|f| (f.abs_path_str(), f.source_str().is_none()));
        files.dedup_by_key(|f| f.abs_path_str());

        let path_to_fileid = files
            .iter()
            .enumerate()
            .map(|(i, f)| (f.abs_path_str(), FileId(i as u32)))
            .collect::<HashMap<_, _>>();

        let files = files
            .into_iter()
            .map(|file_entry| FileInfo {
                path: file_entry.abs_path_str(),
                source: file_entry.source_str().map(|x| x.into_owned()),
                line_coverage: FileLineCoverage::default(),
            })
            .collect::<Vec<_>>();

        drop(object);
        drop(debug_session);

        Ok(Self {
            mod_spec,
            files,
            path_to_fileid,
        })
    }

    pub(crate) fn process_line_coverage(&mut self, sess: &JitFuzzingSession) {
        tracy_full::zone!("ReportInfo::process_line_coverage");
        let mod_spec = self.mod_spec.clone();
        let mut instrumented_offsets = BTreeSet::new();
        let mut covered_offsets = BTreeSet::new();
        for func in &self.mod_spec.functions {
            let base = func.operators_wasm_bin_offset_base as u64;

            // let mut addrs = Vec::new();
            for (i, &off_rel) in func.operator_offset_rel.iter().enumerate() {
                let addr = base + off_rel as u64;
                if sess
                    .get_pass::<BBCoveragePass>()
                    .coverage
                    .saved_val(&Location {
                        function: func.idx,
                        index: func.operator_basic_block[i].0,
                    })
                {
                    // addrs.push(addr);
                    covered_offsets.insert(addr);
                }
                instrumented_offsets.insert(addr);
            }
            // covered_offsets.extend(addrs);
            // if !addrs.is_empty() {
            //     covered_offsets.push(addrs);
            // }
        }

        for addr in instrumented_offsets {
            resolve_source_location(&mod_spec, addr, |x| {
                for x in x {
                    if x.line() == 0 {
                        continue;
                    }
                    if let Some(file) = x.file() {
                        let file_id = self.path_to_fileid[&file.full_path()];
                        self.files[file_id.0 as usize]
                            .line_coverage
                            .set_instrumented(x.line() as usize - 1);
                    }
                }
            });
        }

        for addr in covered_offsets {
            resolve_source_location(&mod_spec, addr, |x| {
                for x in x {
                    if x.line() == 0 {
                        continue;
                    }
                    if let Some(file) = x.file() {
                        let file_id = self.path_to_fileid[&file.full_path()];
                        self.files[file_id.0 as usize]
                            .line_coverage
                            .set_covered(x.line() as usize - 1);
                    }
                }
            });
        }
    }

    pub(crate) fn write_html_report(&self, output_path: &PathBuf) {
        tracy_full::zone!("ReportInfo::write_html_report");
        let mut files = Vec::new();
        // let mut covered: Vec<_> = covered.into_iter().collect();
        // covered.sort_by_cached_key(|(key, _)| (!key.starts_with('/'), key.clone()));
        for file_info in &self.files {
            let coverage = file_info.line_coverage.clone();
            files.push(IndexFile {
                relative_filename: file_info.path.clone(),
                html_filename: file_info.path.replace(['/', ':'], "_") + ".html",
                nums: Counters {
                    n_statements: coverage.instrumented.count_ones(),
                    n_executed: coverage.covered.count_ones(),
                    n_missing: coverage.instrumented.count_ones() - coverage.covered.count_ones(),
                    ..Default::default()
                },
                coverage,
                is_stdlib: file_info.path.contains("wasisdk://")
                    || file_info.path.contains("/wasi-sysroot/")
                    || file_info.path.contains("/rustlib/"),
            });
        }

        let _ = std::fs::create_dir(output_path);
        std::fs::write(
            output_path.join("coverage_html.js"),
            include_str!("../../templates/coverage_html.js"),
        )
        .unwrap();
        std::fs::write(
            output_path.join("style.css"),
            include_str!("../../templates/style.css"),
        )
        .unwrap();

        let totals = files
            .iter()
            .map(|x| &x.nums)
            .fold(Counters::default(), Counters::add);
        let index = IndexTemplate {
            totals,
            files: &files,
            harness_name: &self.mod_spec.filename,
        };
        std::fs::write(output_path.join("index.html"), index.render().unwrap()).unwrap();

        let ss = SyntaxSet::load_defaults_newlines();
        for (file, _file) in files.iter().zip(self.files.iter()) {
            tracy_full::zone!("ReportInfo render file cov report");
            print!(
                "emitting html cov for: {}{}\r",
                file.relative_filename,
                " ".repeat(5)
            );
            let path = PathBuf::from(&file.relative_filename);
            let Some(source) = &_file.source else {
                let t = FileTemplate {
                    nums: file.nums.clone(),
                    relative_filename: &file.relative_filename,
                    prev_html: "todo",
                    next_html: "todo",
                    missing_source: true,
                    lines: &[],
                };
                std::fs::write(output_path.join(&file.html_filename), t.render().unwrap()).unwrap();
                continue;
            };

            let extension = path
                .extension()
                .map(|x| x.to_string_lossy())
                .unwrap_or_default();
            let sr = ss
                .find_syntax_by_extension(&extension)
                .unwrap_or_else(|| ss.find_syntax_plain_text());

            let mut html_generator =
                ClassedHTMLLineGenerator::new_with_class_style(sr, &ss, ClassStyle::Spaced);

            let mut lines = Vec::new();
            for (number, line) in LinesWithEndings::from(source).enumerate() {
                let mut html = html_generator
                    .process_line_which_includes_newline(line)
                    .unwrap();
                if html.is_empty() {
                    html += "&nbsp;";
                }
                lines.push(FileLine {
                    number,
                    html,
                    annotate: None,
                    contexts: false,
                    context_list: false,
                    context_str: "",
                    contexts_label: "",
                    css_class: match (
                        file.coverage.instrumented.get(number).map(|x| *x),
                        file.coverage.covered.get(number).map(|x| *x),
                    ) {
                        (Some(true), Some(true)) => "run",
                        (Some(true), _) => "mis",
                        (_, Some(true)) => unreachable!(),
                        (_, _) => "",
                    },
                });
            }

            let t = FileTemplate {
                nums: file.nums.clone(),
                relative_filename: &file.relative_filename,
                prev_html: "todo",
                next_html: "todo",
                missing_source: false,
                lines: &lines,
            };
            std::fs::write(output_path.join(&file.html_filename), t.render().unwrap()).unwrap();
        }

        // generate css files for themes
        let ts = ThemeSet::load_defaults();

        // create dark color scheme css
        let dark_theme = &ts.themes["Solarized (dark)"];
        let css_dark = css_for_theme_with_class_style(dark_theme, ClassStyle::Spaced).unwrap();
        std::fs::write(output_path.join("theme-dark.css"), css_dark).unwrap();

        // create light color scheme css
        let light_theme = &ts.themes["Solarized (light)"];
        let css_light = css_for_theme_with_class_style(light_theme, ClassStyle::Spaced).unwrap();
        std::fs::write(output_path.join("theme-light.css"), css_light).unwrap();
    }
}

pub(crate) fn run(mod_spec: Arc<ModuleSpec>, input_paths: &[PathBuf], opts: &HtmlCovOpts) {
    let sess = run_inputs(mod_spec.clone(), input_paths);

    let output_path = PathBuf::from(&opts.output);

    dbg!();
    let mut report_info = ReportInfo::new(mod_spec).unwrap();
    dbg!();
    report_info.process_line_coverage(&sess);
    dbg!();
    report_info.write_html_report(&output_path);
}

pub(crate) fn write_html_cov_report(
    mod_spec: Arc<ModuleSpec>,
    sess: &JitFuzzingSession,
    output_path: &PathBuf,
) {
    let mut report_info = ReportInfo::new(mod_spec).unwrap();
    report_info.process_line_coverage(sess);
    report_info.write_html_report(output_path);
}

pub struct ClassedHTMLLineGenerator<'a> {
    syntax_set: &'a SyntaxSet,
    parse_state: ParseState,
    scope_stack: ScopeStack,
    style: ClassStyle,
}

impl<'a> ClassedHTMLLineGenerator<'a> {
    pub fn new_with_class_style(
        syntax_reference: &'a SyntaxReference,
        syntax_set: &'a SyntaxSet,
        style: ClassStyle,
    ) -> Self {
        let parse_state = ParseState::new(syntax_reference);
        let scope_stack = ScopeStack::new();
        ClassedHTMLLineGenerator {
            syntax_set,
            parse_state,
            scope_stack,
            style,
        }
    }

    pub fn process_line_which_includes_newline(
        &mut self,
        line: &str,
    ) -> Result<String, syntect::Error> {
        let ops = self.parse_state.parse_line(line, self.syntax_set)?;

        // adapted from `line_tokens_to_classed_spans`
        let repo = SCOPE_REPO.lock().unwrap();
        let mut s = String::with_capacity(line.len() + ops.len() * 8); // a guess
        let mut cur_index = 0;

        // check and skip emty inner <span> tags
        let mut span_empty = false;
        let mut span_start = 0;

        for &scope in self.scope_stack.as_slice() {
            s.push_str("<span class=\"");
            scope_to_classes(&mut s, scope, self.style, &repo);
            s.push_str("\">");
        }

        for (i, ref op) in ops {
            if i > cur_index {
                span_empty = false;
                write!(s, "{}", escape::Escape(&line[cur_index..i]))?;
                cur_index = i
            }
            self.scope_stack
                .apply_with_hook(op, |basic_op, _| match basic_op {
                    BasicScopeStackOp::Push(scope) => {
                        span_start = s.len();
                        span_empty = true;
                        s.push_str("<span class=\"");
                        scope_to_classes(&mut s, scope, self.style, &repo);
                        s.push_str("\">");
                    }
                    BasicScopeStackOp::Pop => {
                        if !span_empty {
                            s.push_str("</span>");
                        } else {
                            s.truncate(span_start);
                        }
                        span_empty = false;
                    }
                })?;
        }
        if cur_index < line.len() {
            write!(s, "{}", escape::Escape(&line[cur_index..line.len() - 1]))?;
        }
        for _ in 0..self.scope_stack.len() {
            s.push_str("</span>");
        }
        Ok(s)
    }
}

fn scope_to_classes(s: &mut String, scope: Scope, style: ClassStyle, repo: &ScopeRepository) {
    for i in 0..(scope.len()) {
        let atom = scope.atom_at(i as usize);
        let atom_s = repo.atom_str(atom);
        if i != 0 {
            s.push(' ')
        }
        match style {
            ClassStyle::Spaced => {}
            ClassStyle::SpacedPrefixed { prefix } => {
                s.push_str(prefix);
            }
            _ => unreachable!(),
        }
        s.push_str(atom_s);
    }
}

mod escape {
    // Copyright 2013 The Rust Project Developers. See the COPYRIGHT
    // file at the top-level directory of this distribution and at
    // http://rust-lang.org/COPYRIGHT.
    //
    // Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
    // http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
    // <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
    // option. This file may not be copied, modified, or distributed
    // except according to those terms.

    //! HTML Escaping
    //!
    //! This module contains one unit-struct which can be used to HTML-escape a
    //! string of text (for use in a format string).

    use std::fmt;

    /// Wrapper struct which will emit the HTML-escaped version of the contained
    /// string when passed to a format string.
    pub struct Escape<'a>(pub &'a str);

    impl fmt::Display for Escape<'_> {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            // Because the internet is always right, turns out there's not that many
            // characters to escape: http://stackoverflow.com/questions/7381974
            let Escape(s) = *self;
            let pile_o_bits = s;
            let mut last = 0;
            for (i, ch) in s.bytes().enumerate() {
                match ch as char {
                    '<' | '>' | '&' | '\'' | '"' => {
                        fmt.write_str(&pile_o_bits[last..i])?;
                        let s = match ch as char {
                            '>' => "&gt;",
                            '<' => "&lt;",
                            '&' => "&amp;",
                            '\'' => "&#39;",
                            '"' => "&quot;",
                            _ => unreachable!(),
                        };
                        fmt.write_str(s)?;
                        last = i + 1;
                    }
                    _ => {}
                }
            }

            if last < s.len() {
                fmt.write_str(&pile_o_bits[last..])?;
            }
            Ok(())
        }
    }
}
