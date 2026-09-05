use crate::{
    AbortCode,
    fuzzer::{FuzzOpts, Worker, WorkerExit},
    ir::ModuleSpec,
    jit::{JitFuzzingSession, Stats, module::TrapKind},
    simple_bus::MessageBus,
};
use clap::Parser;
use std::sync::{Arc, Mutex};

struct TestModule {
    name: &'static str,
    module: Vec<u8>,
}

impl TestModule {
    fn compile_simple_rust_expr(name: &'static str, expr: &str) -> Self {
        static FS_LOCK: Mutex<()> = Mutex::new(());
        let _fs_guard = FS_LOCK.lock().unwrap();
        let mut code = "".to_owned();
        code += "#[no_mangle]\n";
        code += "pub extern \"C\" fn wasmfuzz_malloc(size: usize) -> *mut u8 {\n";
        code += "    unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(size, 8)) }\n";
        code += "}\n";
        code += "#[no_mangle]\n";
        code += "pub extern \"C\" fn LLVMFuzzerTestOneInput(buf: *const u8, len: usize) {\n";
        code += "    let data = unsafe { std::slice::from_raw_parts(buf, len) };\n";
        code += "    let found = ";
        code += expr;
        code += ";\n";
        code += "    if found { panic!() }\n";
        code += "}\n";
        let id = format!("{:x}", md5::compute(code.as_bytes()));
        let code_path = format!("/tmp/wasmfuzz-test-{id}.rs");
        let mod_path = format!("/tmp/wasmfuzz-test-{id}.wasm");
        if let Ok(module) = std::fs::read(&mod_path) {
            return Self { name, module };
        }
        std::fs::write(&code_path, code).unwrap();
        std::process::Command::new("rustc")
            .arg("--crate-type=cdylib")
            .arg("--target=wasm32-wasip1")
            .arg("--edition=2021")
            .args(["-C", "codegen-units=1"])
            .args(["-C", "link-dead-code=no"])
            .args(["-C", "overflow-checks=no"])
            .arg("-g")
            .arg(&code_path)
            .arg("-o")
            .arg(&mod_path)
            .status()
            .expect("failed to compile Rust snippet to WASM");
        let module = std::fs::read(&mod_path).unwrap();
        Self { name, module }
    }

    fn u8_cmp_one_per_function() -> Self {
        Self::compile_simple_rust_expr(
            "u8-cmp-chain-4",
            "{
                fn check_1(d: &[u8]) -> bool { d[0] == 1 }
                fn check_2(d: &[u8]) -> bool { d[1] == 2 }
                fn check_3(d: &[u8]) -> bool { d[2] == 3 }
                fn check_4(d: &[u8]) -> bool { d[3] == 4 }
                data.len() == 4 && check_1(data) && check_2(data) && check_3(data) && check_4(data)
            }",
        )
    }

    fn u8_cmp_chain_4() -> Self {
        Self::compile_simple_rust_expr(
            "u8-cmp-chain-4",
            "data.len() == 4 && data[0] == 1 && data[1] == 2 && data[2] == 3 && data[3] == 4",
        )
    }

    fn u64_cmp() -> Self {
        Self::compile_simple_rust_expr(
            "u64-cmp",
            "data.len() == 8 && data.try_into().map(u64::from_be_bytes).unwrap() == 0xdeadbeefcafebabe",
        )
    }

    fn hashset_lookup() -> Self {
        Self::compile_simple_rust_expr(
            "hashset-lookup",
            "{ use std::collections::HashSet; let mut col = HashSet::new(); col.insert(&b\"the_target_key\"[..]); col.contains(&data) }",
        )
    }

    fn path_cov_test() -> Self {
        let mut expr = String::new();
        expr += "{ if data.len() != 8 { return; }";
        expr += "let data: [u8; 8] = data.try_into().unwrap(); ";
        expr += "let mut cnt = 0; ";
        for i in 0..8 {
            expr += &format!("if data[{i}] == {i} {{ cnt += 1; }};");
            // expr += &format!("if data[{}] == {} {{ cnt -= 1; }};", i, 0xf0 + i);
        }
        expr += " cnt == 8 }";
        Self::compile_simple_rust_expr("path-cov-test", &expr)
    }

    fn input_len_eq_2048() -> Self {
        Self::compile_simple_rust_expr("input-len-eq-2048", "data.len() == 2048")
    }

    // Exercises the write paths software dirty tracking has to cover: plain
    // stores, unaligned stores, `memory.fill` / `memory.copy` (which go through
    // host builtins rather than JITted stores), and allocations big enough to
    // grow the heap.
    fn memory_churn() -> Self {
        Self::compile_simple_rust_expr(
            "memory-churn",
            "{
                let mut v = vec![0u8; 300 * 1024];
                let vlen = v.len();
                for (i, b) in data.iter().enumerate() {
                    v[(i * 4099) % vlen] = *b;
                    // unaligned multi-byte store, straddles a page now and then
                    let off = (i * 4093) % (vlen - 8);
                    v[off..off + 8].copy_from_slice(&(*b as u64).to_le_bytes());
                }
                let mut s = vec![0xabu8; 70000];
                let n = data.len().min(s.len() / 2);
                s[..n].copy_from_slice(&data[..n]);
                s.copy_within(0..n, 1000);
                let mut total = 0usize;
                for b in v.iter().chain(s.iter()) { total = total.wrapping_add(*b as usize); }
                total == 0xdeadbeef
            }",
        )
    }

    fn from_wat(name: &'static str, wat: &str) -> Self {
        Self {
            name,
            module: wat::parse_str(wat).unwrap(),
        }
    }

    // A single call site whose argument is the first input byte.
    fn call_param_byte() -> Self {
        Self::from_wat(
            "call-param-byte",
            r#"(module
                (memory 2)
                (func $observe (param $arg i32))
                (func (export "malloc") (param $size i32) (result i32) (i32.const 0))
                (func (export "LLVMFuzzerTestOneInput") (param $ptr i32) (param $len i32)
                    (call $observe (i32.load8_u (local.get $ptr))))
            )"#,
        )
    }

    // A store and a load that both carry a non-zero `offset=` immediate, at
    // addresses that don't depend on the input. The effective addresses are
    // 16 + 0x2000 and 32 + 0x3000.
    fn memory_offset_ops() -> Self {
        Self::from_wat(
            "memory-offset-ops",
            r#"(module
                (memory 8)
                (global $bump (mut i32) (i32.const 0x10000))
                (func (export "malloc") (param $size i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $bump))
                    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
                    (local.get $ptr))
                (func (export "LLVMFuzzerTestOneInput") (param $ptr i32) (param $len i32)
                    (i32.store offset=0x2000 (i32.const 16) (local.get $len))
                    (drop (i32.load offset=0x3000 (i32.const 32))))
            )"#,
        )
    }
}

// Runs a fixed input sequence under one snapshot provider and returns the
// coverage-novelty sequence plus a digest of the restored heap.
//
// A provider that misses a dirty page leaves stale bytes behind after restore,
// which makes execution history-dependent -- so both the novelty sequence and
// the digest diverge from the kernel-backed providers.
fn snapshot_provider_trace(
    provider: &str,
    test_module: &TestModule,
    inputs: &[&[u8]],
) -> (Vec<bool>, [u8; 16]) {
    crate::jit::vmcontext::set_snapshot_provider_override(Some(provider));
    let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
    let mut stats = Stats::default();
    let mut opts = FuzzOpts::parse_from(vec!["wasmfuzz-fuzz", "test.wasm"]);
    opts.i.cov_edges = true.into();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(opts.i.to_feedback_opts())
        // the point of the test: make every execution start from a restore
        .run_from_snapshot(true)
        .build();
    sess.initialize(&mut stats);

    let novel = inputs
        .iter()
        .map(|inp| sess.run(inp, &mut stats).novel_coverage)
        .collect();

    // one more restore, so what we digest is the state the next execution
    // would actually start from
    let instance = sess.reusable_stage.instance.as_mut().unwrap();
    instance.vmctx.restore();
    let digest = *md5::compute(instance.vmctx.heap());

    crate::jit::vmcontext::set_snapshot_provider_override(None);
    (novel, digest)
}

#[test]
fn test_software_dirty_tracking_matches_kernel_providers() {
    let inputs: Vec<Vec<u8>> = (0..24u8)
        .map(|i| {
            let len = 1 + (i as usize * 37) % 900;
            (0..len).map(|j| (j as u8).wrapping_mul(i | 1)).collect()
        })
        .collect();
    let inputs: Vec<&[u8]> = inputs.iter().map(|x| x.as_slice()).collect();

    // Two targets on purpose. `memory_churn` covers the bulk-memory builtins
    // and lots of scattered stores, but it allocates so heavily that the input
    // buffer's page ends up marked by allocator traffic anyway -- which hides a
    // missing mark in `write_input`. `u8_cmp_chain_4` allocates nothing, so
    // nothing but the input write touches that page.
    for module in [TestModule::memory_churn(), TestModule::u8_cmp_chain_4()] {
        let reference = snapshot_provider_trace("cow", &module, &inputs);
        // paranoid first: it points at the exact offset of a missed mark,
        // whereas the differential comparison only says "something diverged"
        for provider in ["software-paranoid", "software"] {
            let got = snapshot_provider_trace(provider, &module, &inputs);
            assert_eq!(
                got.0, reference.0,
                "{}/{provider}: coverage novelty diverged from cow",
                module.name
            );
            assert_eq!(
                got.1, reference.1,
                "{}/{provider}: restored heap diverged from cow",
                module.name
            );
        }
        if crate::cow_memory::RestoreDirtyLKMMapping::is_available() {
            let got = snapshot_provider_trace("lkm", &module, &inputs);
            assert_eq!(got.0, reference.0, "{}/lkm: novelty diverged", module.name);
            assert_eq!(got.1, reference.1, "{}/lkm: heap diverged", module.name);
        }
    }
}

struct Fuzzer {
    opts: FuzzOpts,
}

impl Fuzzer {
    fn with_config<F: FnOnce(&mut FuzzOpts)>(f: F) -> Self {
        let mut opts = FuzzOpts::parse_from(vec!["wasmfuzz-fuzz", "test.wasm"]);
        opts.verbose_corpus = true;

        opts.i.cov_funcs = false.into();
        opts.i.cov_bbs = false.into();
        opts.i.cov_edges = false.into();
        opts.i.cmpcov_hamming = false.into();
        opts.i.cmpcov_absdist = false.into();
        opts.i.perffuzz_func = false.into();
        opts.i.perffuzz_bb = false.into();
        opts.i.call_value_profile = false.into();
        opts.i.cov_func_input_size = false.into();
        opts.i.cov_func_input_size_cyclic = false.into();

        opts.x.use_cmplog = false.into();
        opts.x.exhaustive_stage = false.into();
        opts.x.mopt = true.into();
        opts.x.run_from_snapshot = true.into();

        f(&mut opts);
        Self { opts }
    }

    fn assert_solves(&self, test_module: TestModule, timeout_steps: u64) -> &Self {
        let mut opts = self.opts.clone();
        opts.t.timeout_steps = Some(timeout_steps);
        // opts.rng_seed = Some(42);
        let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
        let mut worker = Worker::new(mod_spec, opts, MessageBus::new(), 0, None);
        let res = worker.run().unwrap();
        println!();
        println!();
        println!();
        dbg!(&test_module.name);
        dbg!(&worker.stats);
        println!();
        println!();
        println!();
        // in cmplog runs, we sometimes see solves within the first few execs
        if !*self.opts.x.use_cmplog {
            assert!(
                worker.stats.reusable_stage_executions > 100,
                "did we do anything?"
            );
            assert!(worker.schedule.steps > 100, "did we do anything?");
        }
        assert_eq!(res, WorkerExit::CrashFound);
        self
    }

    fn assert_feedback_run(
        &self,
        test_module: TestModule,
        run: &[&[&[u8]]],
        crasher: &[u8],
    ) -> &Self {
        let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
        let mut stats = Stats::default();
        let mut sess = JitFuzzingSession::builder(mod_spec.clone())
            .feedback(self.opts.i.to_feedback_opts())
            .build();
        sess.initialize(&mut stats);
        for subrun in run {
            for (i, inp) in subrun.iter().enumerate() {
                let interesting = i == 0;
                eprintln!("i={i} inp: {inp:x?}");
                let res = sess.run(inp, &mut stats);
                assert_eq!(
                    res.novel_coverage, interesting,
                    "unexpected feedback result"
                );
            }
        }
        eprintln!("crasher: {crasher:x?}");
        let res = sess.run(crasher, &mut stats);
        assert_eq!(
            res.trap_kind,
            Some(TrapKind::Abort(AbortCode::UnreachableReached))
        );
        self
    }
}

// Source paths of the generated harness that `spec`'s fuzz entrypoint maps to.
fn harness_source_files(spec: &ModuleSpec) -> std::collections::BTreeSet<String> {
    use crate::ir::debuginfo_helper::resolve_source_location;

    // note: the exported symbol is a wasi `.command_export` shim without debug
    // info of its own, so go by name and take the actual harness body too
    let funcs = spec
        .functions
        .iter()
        .filter(|f| f.symbol.contains("LLVMFuzzerTestOneInput"));
    let mut res = std::collections::BTreeSet::new();
    for func in funcs {
        for rel in &func.operator_offset_rel {
            let addr = func.operators_wasm_bin_offset_base as u64 + *rel as u64;
            resolve_source_location(spec, addr, |locs| {
                for loc in locs {
                    if let Some(file) = loc.file() {
                        let path = file.full_path();
                        // ignore inlined std frames, we only want our own snippet
                        if path.starts_with("/tmp/wasmfuzz-test-") {
                            res.insert(path);
                        }
                    }
                }
            });
        }
    }
    res
}

// The symcache is per module, not per thread: a thread that resolves addresses
// for one module and then another must not get the first module's debug info
// back for the second.
#[test]
fn test_symcache_resolves_two_modules_on_one_thread() {
    let a = ModuleSpec::parse("a.wasm", &TestModule::u8_cmp_chain_4().module).unwrap();
    let b = ModuleSpec::parse("b.wasm", &TestModule::input_len_eq_2048().module).unwrap();

    let a_files = harness_source_files(&a);
    let b_files = harness_source_files(&b);
    // ... and going back to the first module doesn't disturb anything either
    let a_files_again = harness_source_files(&a);

    assert!(!a_files.is_empty(), "no debug info resolved for module a");
    assert!(!b_files.is_empty(), "no debug info resolved for module b");
    assert!(
        a_files.is_disjoint(&b_files),
        "modules resolved to the same source: {a_files:?} / {b_files:?}"
    );
    assert_eq!(a_files, a_files_again);
}

// The call parameter value set should report a value we haven't seen before as
// novel even when it sits inside the range the range pass already covers -- and
// should stop doing so once the site has collected more values than the set can
// hold.
#[test]
fn test_instrumentation_call_params_value_set() {
    let test_module = TestModule::call_param_byte();
    let opts = Fuzzer::with_config(|opts| opts.i.call_value_profile = true.into()).opts;
    let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(opts.i.to_feedback_opts())
        .build();
    sess.initialize(&mut stats);
    let mut run = |sess: &mut JitFuzzingSession, byte: u8| {
        sess.run(&[byte], &mut stats).novel_coverage_passes
    };

    assert!(run(&mut sess, 0).contains(&"call-params-set"));
    assert!(run(&mut sess, 100).contains(&"call-params-set"));

    // 50 is inside the [0, 100] range we've already seen, so the range pass has
    // nothing to say -- only the set pass can tell this value is new
    let novel = run(&mut sess, 50);
    assert!(novel.contains(&"call-params-set"));
    assert!(!novel.contains(&"call-params-range"));
    assert!(run(&mut sess, 50).is_empty(), "not a new value");

    // fill the ValueSet<8> up: 5 more distinct values, then one that overflows
    for byte in [10, 20, 30, 40, 60] {
        assert!(run(&mut sess, byte).contains(&"call-params-set"));
    }
    assert!(run(&mut sess, 70).contains(&"call-params-set"), "saturates");
    // saturated: the site is `top` now and can't report anything new again
    assert!(run(&mut sess, 80).is_empty());
}

// `CmpDistU16Pass` has no distance metric for floats, so it shouldn't claim
// those sites -- the general cmpcov pass still does.
#[test]
fn test_cmpcov_u16dist_skips_float_sites() {
    use crate::instrumentation::{CmpCoveragePass, CmpDistU16Pass, KVInstrumentationPass};

    let test_module = TestModule::from_wat(
        "float-and-int-cmp",
        r#"(module
            (memory 1)
            (func (export "malloc") (param i32) (result i32) (i32.const 0))
            (func (export "LLVMFuzzerTestOneInput") (param $ptr i32) (param $len i32)
                (drop (f64.lt (f64.const 1) (f64.const 2)))
                (drop (i32.lt_u (local.get $len) (i32.const 4))))
        )"#,
    );
    let spec = ModuleSpec::parse("test.wasm", &test_module.module).unwrap();
    assert_eq!(CmpCoveragePass::generate_keys(&spec).count(), 2);
    assert_eq!(CmpDistU16Pass::generate_keys(&spec).count(), 1);
}

// The address profile should cover both loads and stores, and should record
// the effective address (dynamic operand + `offset=` immediate) that the guest
// actually accesses.
#[test]
fn test_instrumentation_memory_op_address_offsets() {
    use crate::instrumentation::{
        FeedbackLattice, KVInstrumentationPass, MemoryOpAddressRangePass,
    };

    let test_module = TestModule::memory_offset_ops();
    let opts = Fuzzer::with_config(|opts| opts.i.cov_memory_op_address = true.into()).opts;
    let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(opts.i.to_feedback_opts())
        .build();
    sess.initialize(&mut stats);
    sess.run(b"AAAA", &mut stats);

    let ranges = sess
        .get_pass::<MemoryOpAddressRangePass>()
        .coverage()
        .iter_saved()
        .filter(|(_, val)| !val.is_bottom())
        .map(|(_, val)| (val.low, val.high))
        .collect::<Vec<_>>();
    // keys are sorted by location: the store comes before the load
    assert_eq!(ranges, vec![(0x2010, 0x2010), (0x3020, 0x3020)]);
}

#[test]
fn test_if_chain_exhaustive() {
    Fuzzer::with_config(|opts| {
        opts.i.cov_edges = true.into();
        opts.x.exhaustive_stage = true.into();
    })
    .assert_solves(TestModule::u8_cmp_chain_4(), 100_000);
}

#[test]
fn test_instrumentation_codecov_edge() {
    Fuzzer::with_config(|opts| opts.i.cov_edges = true.into()).assert_feedback_run(
        TestModule::u8_cmp_chain_4(),
        &[
            &[b"AAAA", b"AAAB", b"BBBB", b"ABCD"],
            &[b"\x01BCD", b"AAAA", b"\x01DEF"],
            &[b"\x01\x02\x03X", b"\x01\x02\x03\x05"],
        ],
        b"\x01\x02\x03\x04",
    );
}

#[test]
fn test_instrumentation_codecov_funcs() {
    Fuzzer::with_config(|opts| opts.i.cov_funcs = true.into()).assert_feedback_run(
        TestModule::u8_cmp_one_per_function(),
        &[
            &[b"AAAA", b"AAAB", b"BBBB", b"ABCD"],
            &[b"\x01BCD", b"AAAA", b"\x01DEF"],
            &[b"\x01\x02\x03X", b"\x01\x02\x03\x05"],
        ],
        b"\x01\x02\x03\x04",
    );
}

#[test]
fn test_instrumentation_codecov_bb() {
    Fuzzer::with_config(|opts| opts.i.cov_bbs = true.into()).assert_feedback_run(
        TestModule::u8_cmp_chain_4(),
        &[
            &[b"AAAA", b"AAAB", b"BBBB", b"ABCD"],
            &[b"\x01BCD", b"AAAA", b"\x01DEF"],
            &[b"\x01\x02\x03X", b"\x01\x02\x03\x05"],
        ],
        b"\x01\x02\x03\x04",
    );
}

#[test]
fn test_instrumentation_cmpcov() {
    Fuzzer::with_config(|opts| opts.i.cmpcov_hamming = true.into()).assert_feedback_run(
        TestModule::u64_cmp(),
        &[
            &[b"ABCDABCD"],
            &[b"\xdeBCDABCD", b"\xffBCDABCD"],
            &[b"\xde\xad\xbe\xefABCD"],
            &[b"\xde\xad\xbe\xefABC\xbe"],
            &[b"\xde\xad\xbe\xefABc\xbe"],
            &[b"\xde\xad\xbe\xefAB\xbe\xbe"],
        ],
        b"\xde\xad\xbe\xef\xca\xfe\xba\xbe",
    );
}

#[test]
fn test_if_chain_plain() {
    Fuzzer::with_config(|opts| {
        opts.i.cov_edges = true.into();
    })
    .assert_solves(TestModule::u8_cmp_chain_4(), 1_000_000);
}

#[test]
fn test_u64_compare_cmpcov_exh() {
    Fuzzer::with_config(|opts| {
        opts.i.cmpcov_hamming = true.into();
        opts.x.exhaustive_stage = true.into();
    })
    .assert_solves(TestModule::u64_cmp(), 500_000);
}

#[test]
fn test_u64_compare_cmpcov_plain() {
    Fuzzer::with_config(|opts| {
        opts.i.cmpcov_hamming = true.into();
    })
    .assert_solves(TestModule::u64_cmp(), 5_000_000);
}

#[test]
fn test_cmplog() {
    Fuzzer::with_config(|opts| {
        opts.i.cov_funcs = true.into();
        opts.i.cmpcov_hamming = false.into();
        opts.x.use_cmplog = true.into();
    })
    .assert_solves(TestModule::u64_cmp(), 150_000);
}

#[test]
fn test_hashmap() {
    Fuzzer::with_config(|opts| {
        opts.i.cov_funcs = true.into();
    })
    .assert_feedback_run(
        TestModule::hashset_lookup(),
        &[&[b"NOT_IN_THE_SET"]],
        b"the_target_key",
    );
    // cmplog is good stuff
    Fuzzer::with_config(|opts| {
        opts.i.cov_funcs = true.into();
        opts.i.cov_edges = true.into();
        opts.i.cmpcov_hamming = false.into();
        opts.x.use_cmplog = true.into();
    })
    .assert_solves(TestModule::hashset_lookup(), 4_000_000);
}

#[test]
fn test_path_cov() {
    Fuzzer::with_config(|opts| {
        opts.i.cov_funcs = true.into();
        opts.i.cov_edges = true.into();
        opts.i.path_hash_edge = true.into();
    })
    .assert_solves(TestModule::path_cov_test(), 5_000_000);
}

#[test]
fn test_input_len_eq_2048() {
    Fuzzer::with_config(|opts| {
        opts.i.cmpcov_absdist = true.into();
    })
    .assert_feedback_run(
        TestModule::input_len_eq_2048(),
        &[
            // lower sensitivity for larger distances
            &[&[b'A'; 3], &[b'A'; 4], &[b'A'; 5], &[b'A'; 1000]],
            &[&[b'A'; 1025], &[b'A'; 1026], &[b'A'; 1027]],
            // high sensitivity for small distances
            &[&[b'A'; 2044]],
            &[&[b'A'; 2045]],
            &[&[b'A'; 2046]],
            &[&[b'A'; 2047]],
        ],
        &[b'A'; 2048],
    );

    Fuzzer::with_config(|opts| {
        opts.i.cmpcov_u16dist = true.into();
    })
    .assert_feedback_run(
        TestModule::input_len_eq_2048(),
        &[
            &[&[b'A'; 3]],
            &[&[b'A'; 4]],
            &[&[b'A'; 5]],
            &[&[b'A'; 6]],
            &[&[b'A'; 1025]],
            &[&[b'A'; 1026]],
            &[&[b'A'; 1027]],
            &[&[b'A'; 2046]],
            &[&[b'A'; 2047]],
        ],
        &[b'A'; 2048],
    )
    .assert_solves(TestModule::input_len_eq_2048(), 1_000_000);
}

#[test]
#[should_panic]
fn test_input_len_eq_2048_fails() {
    Fuzzer::with_config(|opts| {
        opts.i.cmpcov_absdist = true.into();
    })
    .assert_solves(TestModule::input_len_eq_2048(), 1_000_000);
}
