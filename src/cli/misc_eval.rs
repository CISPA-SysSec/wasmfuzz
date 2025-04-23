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
        println!("{:?}", inp);
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
        println!("{}", log_line);
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
        let gen = crate::jit::FullFeedbackPasses {
            opts: feedback,
            spec: mod_spec.clone(),
        };
        gen.generate_passes()
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
        println!("{}", log_line);
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
        println!("{}", log_line);
        out_file.write_all(log_line.as_bytes()).unwrap();
        out_file.write_all(b"\n").unwrap();
    }
}

pub(crate) fn eval_snapshot_perf(pages: usize, touch: usize, iters: usize) {
    assert!(RestoreDirtyLKMMapping::is_available());
    use crate::cow_memory::*;
    use rand::seq::SliceRandom;
    #[derive(Debug)]
    enum Provider {
        Dummy,
        CoW,
        Criu,
        Lkm,
    }
    let accessible_size = pages << 12;
    let mapping_size = accessible_size;
    let mut page_offsets = (0..pages).map(|x| x << 12).collect::<Vec<_>>();
    let mut rng = rand::rng();

    for provider in &[
        Provider::Dummy,
        Provider::CoW,
        Provider::Criu,
        Provider::Lkm,
    ] {
        dbg!(provider);
        let mut mapping: Box<dyn ResettableMapping> = match provider {
            Provider::Dummy => Box::new(DummyMapping::new(accessible_size, mapping_size)),
            Provider::CoW => Box::new(CowResetMapping::new(accessible_size, mapping_size)),
            Provider::Criu => Box::new(CriuMapping::new(accessible_size, mapping_size)),
            Provider::Lkm => Box::new(RestoreDirtyLKMMapping::new(accessible_size, mapping_size)),
        };

        mapping.restore();
        dbg!(provider);

        let mut chksum = 0;
        let start = Instant::now();
        for _ in 0..iters {
            let slice = mapping.as_mut_slice();
            page_offsets.shuffle(&mut rng);
            page_offsets
                .iter()
                .take(touch)
                .for_each(|&i| slice[i] = 0x42);
            mapping.restore();
            let slice = mapping.as_slice();
            chksum += page_offsets
                .iter()
                .take(touch)
                .map(|&i| slice[i] as usize)
                .sum::<usize>();
        }
        println!(
            "{:?}: {:?} (chksum: {:#x})",
            provider,
            start.elapsed(),
            chksum
        )
    }
}
