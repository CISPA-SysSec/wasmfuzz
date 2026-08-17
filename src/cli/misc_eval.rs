use std::{fs::File, io::Write, path::PathBuf, time::Instant};

use rand::seq::SliceRandom;

use crate::jit::{FeedbackOptions, JitFuzzingSession, PassesGen, Stats};

use super::parse_program;

pub(crate) fn eval_pass_corr(program: &PathBuf, corpus: &PathBuf, jsonl_out_path: &PathBuf) {
    let mut out_file = File::create(jsonl_out_path).unwrap();
    let mod_spec = parse_program(&PathBuf::from(program));
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(FeedbackOptions::all_instrumentation())
        .build();
    sess.initialize(&mut stats);

    let mut files = std::fs::read_dir(corpus)
        .expect("failed to list corpus dir")
        .flat_map(|el| el.ok())
        .collect::<Vec<_>>();
    files.sort_by_cached_key(|entry| entry.metadata().unwrap().created().unwrap());

    for entry in files {
        let inp = entry.path();
        println!("{inp:?}");
        let testcase = std::fs::read(inp).expect("couldn't read seed");
        assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
        // let before = sess.covdb.features().to_map();
        let res = sess.run_reusable_fresh(&testcase, false, &mut stats);
        res.expect_ok();
        let changed = res.novel_coverage_passes;

        // let check_dom = |a, b| {
        //     if changed.contains(b) {
        //         assert!(changed.contains(a), "unexpected sensitivity break");
        //     };
        // };
        // check_dom("covered_edges", "covered_basic_blocks");
        // check_dom("covered_basic_blocks", "covered_functions");

        let log_line = serde_json::to_string(&changed).unwrap();
        println!("{log_line}");
        out_file.write_all(log_line.as_bytes()).unwrap();
        out_file.write_all(b"\n").unwrap();
    }
}

pub(crate) fn eval_pass_speed(program: &PathBuf, corpus: &PathBuf, jsonl_out_path: &PathBuf) {
    let mut out_file = File::create(jsonl_out_path).unwrap();
    let mod_spec = parse_program(&PathBuf::from(program));
    let mut stats = Stats::default();

    let passes = {
        let feedback = FeedbackOptions::all_instrumentation();
        let generator = crate::jit::FullFeedbackPasses {
            opts: feedback,
            spec: mod_spec.clone(),
        };
        generator.generate_passes()
    };

    let mut configs = passes
        .0
        .into_iter()
        .map(|pass| {
            (
                pass.shortcode().to_owned(),
                Box::new(crate::jit::SinglePassGen::new(pass)) as Box<dyn PassesGen>,
            )
        })
        .collect::<Vec<_>>();

    configs.push(("<nothing>".to_owned(), Box::new(crate::jit::EmptyPassesGen)));

    configs.shuffle(&mut rand::rng());

    for i in 0..4 {
        configs.insert(
            i,
            (
                format!("<warmup-{}>", i + 1),
                Box::new(crate::jit::EmptyPassesGen),
            ),
        );
    }

    for (key, generator) in configs {
        dbg!(&key);
        let mut sess = JitFuzzingSession::builder(mod_spec.clone())
            .passes_generator(generator.into())
            .build();
        let reusable_jit_start = Instant::now();
        sess.initialize(&mut stats);
        let reusable_jit_time = reusable_jit_start.elapsed();

        let mut files = std::fs::read_dir(corpus)
            .expect("failed to list corpus dir")
            .flat_map(|el| el.ok())
            .collect::<Vec<_>>();
        files.sort_by_cached_key(|entry| entry.metadata().unwrap().created().unwrap());

        // dummy input for trapping jit timing
        sess.run_reusable(&[0], false, &mut stats).expect_ok();

        let reusable_run_start = Instant::now();
        for entry in &files {
            let inp = entry.path();
            let testcase = std::fs::read(inp).expect("couldn't read seed");
            assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
            sess.run_reusable(&testcase, false, &mut stats).expect_ok();
        }
        let reusable_run_time = reusable_run_start.elapsed();

        let log_obj = serde_json::json!({
            "pass": &key,
            "reusable_run_seconds": reusable_run_time.as_secs_f32(),
            "reusable_jit_seconds": reusable_jit_time.as_secs_f32(),
            "reusable_jit_code_bytes": sess.reusable_stage.instance.as_ref().unwrap().code_size,
        });
        let log_line = serde_json::to_string(&log_obj).unwrap();
        println!("{log_line}");
        out_file.write_all(log_line.as_bytes()).unwrap();
        out_file.write_all(b"\n").unwrap();
    }
}

pub(crate) fn eval_pages_touched(program: &PathBuf, corpus: &PathBuf, jsonl_out_path: &PathBuf) {
    let mut out_file = File::options()
        .create(true)
        .append(true)
        .open(jsonl_out_path)
        .unwrap();

    let mod_spec = parse_program(&PathBuf::from(program));

    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec.clone()).build();
    sess.initialize(&mut stats);

    let mut files = std::fs::read_dir(corpus)
        .expect("failed to list corpus dir")
        .flat_map(|el| el.ok())
        .collect::<Vec<_>>();
    files.sort_by_cached_key(|entry| entry.metadata().unwrap().created().unwrap());

    for entry in &files {
        let inp = entry.path();
        let testcase = std::fs::read(&inp).expect("couldn't read seed");
        assert!(testcase.len() <= crate::TEST_CASE_SIZE_LIMIT);
        sess.run_reusable_fresh(&testcase, false, &mut stats)
            .expect_ok();
        let reusable_instance = sess.reusable_stage.instance.as_mut().unwrap();
        let modified_4k = reusable_instance
            .vmctx
            .heap_alloc
            .count_modified_pages(1 << 12);
        let modified_64k = reusable_instance
            .vmctx
            .heap_alloc
            .count_modified_pages(1 << 16);
        let pages_64k = reusable_instance.vmctx.heap_pages;
        let pages_4k = pages_64k * (1 << (16 - 12));

        let test_case = inp.file_name().unwrap().to_string_lossy();
        let log_obj = serde_json::json!({
            "target": mod_spec.filename,
            "test_case": test_case,
            "modified_4k": modified_4k,
            "modified_64k": modified_64k,
            "pages_64k": pages_64k,
            "pages_4k": pages_4k,
        });
        let log_line = serde_json::to_string(&log_obj).unwrap();
        println!("{log_line}");
        out_file.write_all(log_line.as_bytes()).unwrap();
        out_file.write_all(b"\n").unwrap();
    }
}

pub(crate) fn eval_snapshot_perf(pages: usize, touch: usize, iters: usize, threads: usize) {
    use crate::cow_memory::*;
    use rand::seq::SliceRandom;
    #[derive(Debug, Clone, Copy)]
    enum Provider {
        Dummy,
        CoW,
        Criu,
        Lkm,
        UffdWpAsync,
        UffdWpAsyncRescan,
        UffdWpAsyncSparse,
        UffdWpAsyncSparseRescan,
        SoftwareLog,
        SoftwareBitmap,
    }
    let accessible_size = pages << 12;
    let mapping_size = accessible_size;

    for provider in &[
        Provider::Dummy,
        Provider::CoW,
        Provider::Criu,
        Provider::Lkm,
        Provider::UffdWpAsync,
        Provider::UffdWpAsyncRescan,
        Provider::UffdWpAsyncSparse,
        Provider::UffdWpAsyncSparseRescan,
        Provider::SoftwareLog,
        Provider::SoftwareBitmap,
    ] {
        match provider {
            Provider::Lkm if !RestoreDirtyLKMMapping::is_available() => {
                println!("{provider:?}: unavailable (/dev/restore-dirty)");
                continue;
            }
            Provider::UffdWpAsync
            | Provider::UffdWpAsyncRescan
            | Provider::UffdWpAsyncSparse
            | Provider::UffdWpAsyncSparseRescan
                if !UffdWpAsyncMapping::is_available() =>
            {
                println!("{provider:?}: unavailable (userfaultfd WP_ASYNC)");
                continue;
            }
            _ => {}
        }
        let new_mapping = || -> Box<dyn ResettableMapping> {
            match provider {
            Provider::Dummy => Box::new(DummyMapping::new(accessible_size, mapping_size)),
            Provider::CoW => Box::new(CowResetMapping::new(accessible_size, mapping_size)),
            Provider::Criu => Box::new(CriuMapping::new(accessible_size, mapping_size)),
            Provider::Lkm => Box::new(RestoreDirtyLKMMapping::new(accessible_size, mapping_size)),
            Provider::UffdWpAsync | Provider::UffdWpAsyncRescan => {
                Box::new(UffdWpAsyncMapping::new_with_options(
                    accessible_size,
                    mapping_size,
                    UffdWpAsyncOptions {
                        track_unpopulated: true,
                        rearm_via_scan: matches!(provider, Provider::UffdWpAsyncRescan),
                    },
                ))
            }
            Provider::UffdWpAsyncSparse | Provider::UffdWpAsyncSparseRescan => {
                Box::new(UffdWpAsyncMapping::new_with_options(
                    accessible_size,
                    mapping_size,
                    UffdWpAsyncOptions {
                        track_unpopulated: false,
                        rearm_via_scan: matches!(provider, Provider::UffdWpAsyncSparseRescan),
                    },
                ))
            }
            Provider::SoftwareLog => Box::new(SoftwareDirtyMapping::new_with_mode(
                accessible_size,
                mapping_size,
                DirtyTrackMode::Log,
            )),
            Provider::SoftwareBitmap => Box::new(SoftwareDirtyMapping::new_with_mode(
                accessible_size,
                mapping_size,
                DirtyTrackMode::Bitmap,
            )),
            }
        };

        // One mapping per thread, all in the same address space: that's how the
        // fuzzer runs, and it's the setup where the kernel-backed providers pay
        // for TLB shootdowns to every other worker's core.
        let worker = || {
            let mut mapping = new_mapping();
            let mut rng = rand::rng();
            let mut page_offsets = (0..pages).map(|x| x << 12).collect::<Vec<_>>();
            mapping.restore();
            let mut chksum = 0;
            for _ in 0..iters {
                // partial: shuffling all `pages` offsets per iteration costs
                // more than the restore we're trying to measure
                page_offsets.partial_shuffle(&mut rng, touch);
                for &i in page_offsets.iter().take(touch) {
                    mapping.as_mut_slice()[i] = 0x42;
                    // no-op except for SoftwareDirtyMapping, where it stands in
                    // for the mark the JIT would emit as part of the store
                    mapping.mark_dirty(i, 1);
                }
                mapping.restore();
                let slice = mapping.as_slice();
                chksum += page_offsets
                    .iter()
                    .take(touch)
                    .map(|&i| slice[i] as usize)
                    .sum::<usize>();
            }
            chksum
        };

        let start = Instant::now();
        let chksum: usize = std::thread::scope(|scope| {
            let handles = (0..threads)
                .map(|_| scope.spawn(&worker))
                .collect::<Vec<_>>();
            handles.into_iter().map(|h| h.join().unwrap()).sum()
        });
        let elapsed = start.elapsed();
        let restores = (iters * threads) as f64;
        // Per-restore numbers are wall/(iters*threads), i.e. aggregate
        // throughput rather than the latency a single worker sees.
        println!(
            "{:?}: {:?} for {} restores across {} thread(s) -- {:.3} us/restore, \
             {:.3} us/dirty page (chksum: {:#x})",
            provider,
            elapsed,
            restores as usize,
            threads,
            elapsed.as_secs_f64() * 1e6 / restores,
            elapsed.as_secs_f64() * 1e6 / (restores * touch as f64),
            chksum
        )
    }
}
