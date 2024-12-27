use crate::{
    instrumentation::{
        BBCoveragePass, CodeCovInstrumentationPass, EdgeCoveragePass, FunctionCoveragePass,
    },
    HashSet,
};
use std::{
    io::Write,
    path::PathBuf,
    time::{Instant, SystemTime},
};

use clap::Parser;
use serde::Serialize;

use crate::jit::{FeedbackOptions, JitFuzzingSession, Stats};

#[derive(Debug, Serialize)]
struct MetaPacket {
    target: String,
    bucket: Option<String>,
    start_timestamp: u64, // allow some easy clustering for perf evolution
    #[serde(flatten)]
    first_event: LogEvent,
    interval_secs: f32,
}

#[derive(Debug, Serialize)]
struct LogEvent {
    i: u32,
    // what time did we want to take this snapshot?
    seconds: f32,
    // what time did we actually take this snapshot?
    seconds_rt: f32,
    crashing: bool,
    cov_funcs: u32,
    cov_bbs: u32,
    cov_edges: u32,
    entries: u32,
    finds: u32,
}

#[derive(Parser, Clone)]
pub(crate) struct MonitorCovOpts {
    program: String,
    #[clap(long)]
    dir: String,
    #[clap(long)]
    out_file: Option<String>,
    #[clap(long)]
    continuous: bool,
    #[clap(long, default_value = "1s")]
    interval: humantime::Duration,
    #[clap(long)]
    bucket: Option<String>,
    #[clap(long, default_value = "4096")]
    input_size_limit: usize,
}

pub(crate) fn run(opts: MonitorCovOpts) {
    let MonitorCovOpts {
        program,
        dir,
        out_file,
        interval,
        continuous,
        bucket,
        input_size_limit,
    } = opts;
    let mod_spec = super::parse_program(&PathBuf::from(&program));
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec.clone())
        .feedback(FeedbackOptions::minimal_code_coverage())
        .instruction_limit(Some(2_000_000_000))
        .build();
    sess.initialize(&mut stats);
    let mut corpus = HashSet::default();
    let mut paths_seen = HashSet::default();
    let mut crashes = false;
    let mut finds = 0;

    let start_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut out_file = out_file.map(|path| std::fs::File::create(path).unwrap());
    let start_rt = Instant::now();
    let start = SystemTime::now();
    let mut emit_meta = true;
    for i in 1u32.. {
        let mut has_find = false;
        let target_dur = (*interval) * i;
        if let Ok(sleep_dur) = (start + target_dur).duration_since(SystemTime::now()) {
            std::thread::sleep(sleep_dur);
        }
        for entry in std::fs::read_dir(&dir).expect("failed to list corpus dir") {
            let entry = entry.unwrap();
            // skip libafl's hidden metadata and lock files
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            // Note: we might want to turn this off to handle in-progress writes?
            if !paths_seen.insert(entry.path()) {
                continue;
            }
            match std::fs::read(entry.path()) {
                Ok(data) => {
                    if data.len() > input_size_limit {
                        continue;
                    }
                    if !corpus.insert(data.clone()) {
                        continue;
                    }

                    let res = sess.run(&data, &mut Stats::default());
                    crashes |= res.is_crash();
                    if res.novel_coverage {
                        has_find = true;
                        finds += 1;
                    } else {
                        continue;
                    }
                }
                Err(e) => {
                    eprintln!("{e:?}");
                }
            }
        }

        if continuous || has_find {
            let event = LogEvent {
                i,
                seconds: target_dur.as_secs_f32(),
                seconds_rt: start_rt.elapsed().as_secs_f32(),
                cov_funcs: sess.get_pass::<FunctionCoveragePass>().count_saved() as u32,
                cov_bbs: sess.get_pass::<BBCoveragePass>().count_saved() as u32,
                cov_edges: sess.get_pass::<EdgeCoveragePass>().count_saved() as u32,
                crashing: crashes,
                entries: corpus.len() as u32,
                finds,
            };
            let line = if emit_meta {
                emit_meta = false;
                let event = MetaPacket {
                    first_event: event,
                    target: mod_spec.filename.clone(),
                    bucket: bucket.clone(),
                    interval_secs: interval.as_secs_f32(),
                    start_timestamp,
                };
                serde_json::to_string(&event).unwrap()
            } else {
                serde_json::to_string(&event).unwrap()
            };
            println!("{line}");
            if let Some(file) = out_file.as_mut() {
                file.write_all(line.as_bytes()).unwrap();
                file.write_all(b"\n").unwrap();
            }
        }
    }
}
