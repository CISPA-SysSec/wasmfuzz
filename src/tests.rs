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

    // Round-trips the input through the emulated WASI filesystem: write it to
    // a file, read it back through a fresh handle, compare against a magic.
    fn file_roundtrip_u64_cmp() -> Self {
        Self::compile_simple_rust_expr(
            "file-roundtrip-u64-cmp",
            "{
                use std::io::{Read, Seek, SeekFrom, Write};
                if data.len() != 8 { return; }
                // a stale file from a previous execution must never be visible
                assert!(std::fs::metadata(\"/tmp/roundtrip.bin\").is_err());
                assert!(std::fs::read(\"/tmp/never-written\").is_err());
                let mut f = std::fs::File::create(\"/tmp/roundtrip.bin\").unwrap();
                f.write_all(&data[..4]).unwrap();
                f.write_all(&data[4..]).unwrap();
                drop(f);
                let mut f = std::fs::File::open(\"/tmp/roundtrip.bin\").unwrap();
                let mut tail = [0u8; 4];
                f.seek(SeekFrom::Start(4)).unwrap();
                f.read_exact(&mut tail).unwrap();
                f.seek(SeekFrom::Start(0)).unwrap();
                let mut all = Vec::new();
                f.read_to_end(&mut all).unwrap();
                assert_eq!(all.len(), 8);
                assert_eq!(&all[4..], &tail);
                assert_eq!(std::fs::metadata(\"/tmp/roundtrip.bin\").unwrap().len(), 8);
                std::fs::remove_file(\"/tmp/roundtrip.bin\").unwrap();
                assert!(std::fs::metadata(\"/tmp/roundtrip.bin\").is_err());
                u64::from_be_bytes(all.try_into().unwrap()) == 0xdeadbeefcafebabe
            }",
        )
    }

    // pread/pwrite (sqlite's unixRead/unixWrite) on the emulated filesystem:
    // positioned I/O must not move the fd's cursor.
    fn file_pread_pwrite() -> Self {
        Self::compile_simple_rust_expr(
            "file-pread-pwrite",
            "{
                use std::io::{Seek, Write};
                use std::os::fd::AsRawFd;
                extern \"C\" {
                    fn pread(fd: i32, buf: *mut u8, n: usize, off: i64) -> isize;
                    fn pwrite(fd: i32, buf: *const u8, n: usize, off: i64) -> isize;
                }
                let mut f = std::fs::OpenOptions::new().read(true).write(true).create(true)
                    .open(\"/tmp/pio.bin\").unwrap();
                f.write_all(b\"abcdefgh\").unwrap();
                let fd = f.as_raw_fd();
                assert_eq!(unsafe { pwrite(fd, b\"XY\".as_ptr(), 2, 2) }, 2);
                assert_eq!(unsafe { pwrite(fd, b\"ij\".as_ptr(), 2, 8) }, 2);
                let mut buf = [0u8; 4];
                assert_eq!(unsafe { pread(fd, buf.as_mut_ptr(), 4, 1) }, 4);
                assert_eq!(&buf, b\"bXYe\");
                assert_eq!(unsafe { pread(fd, buf.as_mut_ptr(), 4, 8) }, 2);
                assert_eq!(f.stream_position().unwrap(), 8);
                assert_eq!(std::fs::read(\"/tmp/pio.bin\").unwrap(), b\"abXYefghij\");
                std::fs::remove_file(\"/tmp/pio.bin\").unwrap();
                false
            }",
        )
    }

    // Re-reads a 1 MiB file until the instruction limit hits, which almost
    // always happens while `fd_read` copies the file into guest memory.
    fn file_reread_until_out_of_fuel() -> Self {
        Self::compile_simple_rust_expr(
            "file-reread-until-out-of-fuel",
            "{
                use std::io::{Read, Seek, SeekFrom};
                std::fs::write(\"/tmp/big.bin\", vec![7u8; 1 << 20]).unwrap();
                let mut f = std::fs::File::open(\"/tmp/big.bin\").unwrap();
                let mut buf = vec![0u8; 1 << 20];
                let _ = data;
                loop {
                    f.seek(SeekFrom::Start(0)).unwrap();
                    f.read_exact(&mut buf).unwrap();
                    if std::hint::black_box(&buf)[0] != 7 {
                        break false;
                    }
                }
            }",
        )
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

    // Unbounded recursion when the first input byte is 1. The recursive
    // function takes more integer parameters than fit in registers, so the
    // trailing vmctx parameter is passed on the native stack.
    fn recurse_on_one() -> Self {
        Self::from_wat(
            "recurse-on-one",
            r#"(module
                (memory 2)
                (func $rec (param i32 i32 i32 i32 i32 i32 i32 i32)
                    (call $rec (local.get 0) (local.get 1) (local.get 2) (local.get 3)
                               (local.get 4) (local.get 5) (local.get 6) (local.get 7)))
                (func (export "malloc") (param $size i32) (result i32) (i32.const 0))
                (func (export "LLVMFuzzerTestOneInput") (param $ptr i32) (param $len i32)
                    (if (i32.eq (i32.load8_u (local.get $ptr)) (i32.const 1))
                        (then (call $rec (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                                         (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))))
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
// Guest recursion that exhausts the native stack is reported as a stack-overflow
// abort, not a fault at an unregistered pc, and the session keeps running inputs
// afterwards.
#[test]
fn test_unbounded_recursion_traps_as_stack_overflow() {
    let test_module = TestModule::recurse_on_one();
    let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec).build();
    sess.initialize(&mut stats);
    assert_eq!(sess.run(&[0], &mut stats).trap_kind, None);
    assert_eq!(
        sess.run(&[1], &mut stats).trap_kind,
        Some(TrapKind::Abort(AbortCode::StackOverflow))
    );
    assert_eq!(sess.run(&[0], &mut stats).trap_kind, None);
}

// Branches that carry values out of blocks, `br_table`s with values, `if`s
// with params, loops with params and multi-value block types. Every result is
// checked in-guest, so a miscompile shows up as an `unreachable` trap (or, in
// debug builds, as a verifier error).
fn block_values_module() -> TestModule {
    TestModule::from_wat(
        "block-values",
        r#"(module
            (memory 1)
            (func $check (param $got i32) (param $want i32)
                (if (i32.ne (local.get $got) (local.get $want)) (then unreachable)))
            (func (export "malloc") (param i32) (result i32) (i32.const 0))
            (func (export "LLVMFuzzerTestOneInput") (param $ptr i32) (param $len i32)
                (local $t i32)
                ;; br_if out of a block with a result
                (block (result i32)
                    (i32.const 7) (local.get $len) (br_if 0) (drop) (i32.const 9))
                (call $check (select (i32.const 7) (i32.const 9) (local.get $len)))

                ;; br_if to an inner block whose end is directly followed by
                ;; the outer block's end
                (block $o (result i32)
                    (i32.const 5)
                    (block $i (i32.const 6) (local.get $len) (br_if $i) (drop)))
                (call $check (i32.const 5))

                ;; br_if past two block ends
                (block $o (result i32)
                    (block $i (result i32)
                        (i32.const 1) (local.get $len) (br_if $o) (drop) (i32.const 2)))
                (call $check (select (i32.const 1) (i32.const 2) (local.get $len)))

                ;; br_table carrying a value to different blocks
                (block $a (result i32)
                    (block $b (result i32)
                        (i32.const 10) (local.get $len) (br_table $b $a $b))
                    (i32.const 100) (i32.add))
                (call $check (select (i32.const 10) (i32.const 110)
                    (i32.eq (local.get $len) (i32.const 1))))

                ;; if with params, without and with an else arm
                (i32.const 3) (local.get $len)
                (if (param i32) (result i32) (then (i32.const 1) (i32.add)))
                (call $check (select (i32.const 4) (i32.const 3) (local.get $len)))
                (i32.const 3) (local.get $len)
                (if (param i32) (result i32)
                    (then (i32.const 1) (i32.add))
                    (else (i32.const 2) (i32.mul)))
                (call $check (select (i32.const 4) (i32.const 6) (local.get $len)))

                ;; loop with a param carried by the back edge
                (i32.const 0)
                (loop $l (param i32) (result i32)
                    (i32.const 1) (i32.add)
                    (local.tee $t) (i32.lt_u (local.get $t) (i32.const 5)) (br_if $l))
                (call $check (i32.const 5))

                ;; multi-value block type (refers to a type index, not a function)
                (i32.const 4)
                (block (param i32) (result i32 i32) (local.get $len) (br 0))
                (i32.add)
                (call $check (i32.add (i32.const 4) (local.get $len))))
        )"#,
    )
}

#[test]
fn test_block_values() {
    use crate::jit::{FeedbackOptions, TracingOptions};
    let test_module = block_values_module();
    let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
    for feedback in [
        FeedbackOptions::nothing(),
        FeedbackOptions::all_instrumentation(),
    ] {
        let mut stats = Stats::default();
        let mut sess = JitFuzzingSession::builder(mod_spec.clone())
            .feedback(feedback)
            .tracing(TracingOptions {
                concolic: true,
                ..Default::default()
            })
            .build();
        sess.initialize(&mut stats);
        for len in 0..4 {
            let input = vec![0u8; len];
            assert_eq!(sess.run(&input, &mut stats).trap_kind, None, "len={len}");
            sess.run_tracing_fresh(&input, &mut stats)
                .expect("tracing run should not trap");
        }
    }
}

// Both arms of every `if` (with and without else) are distinct edges, and
// every edge the CFG reports is reachable.
#[test]
fn test_if_edges_covered() {
    use crate::instrumentation::EdgeCoveragePass;
    let test_module = TestModule::from_wat(
        "if-edges",
        r#"(module
            (memory 1)
            (global $g (mut i32) (i32.const 0))
            (func (export "malloc") (param i32) (result i32) (i32.const 0))
            (func (export "LLVMFuzzerTestOneInput") (param $ptr i32) (param $len i32)
                (if (local.get $len) (then (global.set $g (i32.const 1))))
                (if (i32.gt_u (local.get $len) (i32.const 1))
                    (then (global.set $g (i32.const 2)))
                    (else (global.set $g (i32.const 3)))))
        )"#,
    );
    let opts = Fuzzer::with_config(|opts| {
        // function coverage lets `initialize` see progress in malloc
        opts.i.cov_funcs = true.into();
        opts.i.cov_edges = true.into();
    })
    .opts;
    let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(opts.i.to_feedback_opts())
        .build();
    sess.initialize(&mut stats);

    let mut novel = Vec::new();
    for len in [0, 1, 2] {
        novel.push(sess.run(&vec![0; len], &mut stats).novel_coverage);
    }
    assert_eq!(novel, [true, true, true]);
    let cov = &sess.get_pass::<EdgeCoveragePass>().coverage;
    // two edges per if
    assert_eq!(cov.keys.len(), 4);
    assert_eq!(cov.saved.count_ones(), 4, "uncovered edges");
}

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
fn test_wasi_memfs_roundtrip_solves_with_cmplog() {
    Fuzzer::with_config(|opts| {
        opts.i.cov_funcs = true.into();
        opts.i.cmpcov_hamming = false.into();
        opts.x.use_cmplog = true.into();
    })
    .assert_solves(TestModule::file_roundtrip_u64_cmp(), 300_000);
}

#[test]
fn test_wasi_memfs_pread_pwrite() {
    let test_module = TestModule::file_pread_pwrite();
    let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(crate::jit::FeedbackOptions::nothing())
        .build();
    sess.initialize(&mut stats);
    sess.run_tracing_fresh(&[0; 8], &mut stats)
        .expect("pread/pwrite round trip should not trap");
}

// Net bytes allocated by the current thread, to catch host-side leaks.
#[cfg(not(any(feature = "with_mimalloc", feature = "tracy")))]
mod thread_alloc_counter {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static NET_BYTES: Cell<isize> = const { Cell::new(0) };
    }

    fn add(delta: isize) {
        let _ = NET_BYTES.try_with(|n| n.set(n.get() + delta));
    }

    pub(super) fn net_bytes() -> isize {
        NET_BYTES.with(|n| n.get())
    }

    struct Counting;

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            add(layout.size() as isize);
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            add(layout.size() as isize);
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            add(-(layout.size() as isize));
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            add(new_size as isize - layout.size() as isize);
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;
}

// Traps `longjmp` past the builtin that raised them. A builtin that still held
// a buffer at that point leaked it: here 1 MiB per execution.
#[test]
#[cfg(not(any(feature = "with_mimalloc", feature = "tracy")))]
fn test_wasi_memfs_out_of_fuel_in_fd_read_does_not_leak() {
    let test_module = TestModule::file_reread_until_out_of_fuel();
    let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(crate::jit::FeedbackOptions::nothing())
        .instruction_limit(Some(20_000_000))
        .build();
    sess.initialize(&mut stats);
    let mut run = |stats: &mut Stats| {
        assert!(matches!(
            sess.run(&[0], stats).trap_kind,
            Some(TrapKind::OutOfFuel(_))
        ));
    };
    for _ in 0..4 {
        run(&mut stats);
    }
    let before = thread_alloc_counter::net_bytes();
    for _ in 0..32 {
        run(&mut stats);
    }
    let leaked = thread_alloc_counter::net_bytes() - before;
    assert!(leaked < 4 << 20, "leaked {leaked} bytes over 32 executions");
}

// Bytes that went through the emulated filesystem must keep their concolic
// labels, so the final comparison shows up as a symbolic path constraint.
#[test]
fn test_wasi_memfs_keeps_concolic_labels() {
    let test_module = TestModule::file_roundtrip_u64_cmp();
    let mod_spec = Arc::new(ModuleSpec::parse("test.wasm", &test_module.module).unwrap());
    let mut stats = Stats::default();
    let mut sess = JitFuzzingSession::builder(mod_spec)
        .feedback(crate::jit::FeedbackOptions {
            live_funcs: true,
            ..crate::jit::FeedbackOptions::nothing()
        })
        .tracing(crate::jit::TracingOptions {
            concolic: true,
            ..Default::default()
        })
        .build();
    sess.initialize(&mut stats);
    sess.run_tracing_fresh(&[1, 2, 3, 4, 5, 6, 7, 8], &mut stats)
        .expect("tracing run should not trap");
    let vmctx = &sess.tracing_stage.instance.as_ref().unwrap().vmctx;
    let symbolic_branches = vmctx
        .concolic
        .events
        .iter()
        .filter(|ev| {
            matches!(
                ev,
                crate::concolic::ConcolicEvent::PathConstraint { condition, .. }
                    if !condition.is_concrete()
            )
        })
        .count();
    assert!(
        symbolic_branches > 0,
        "no symbolic path constraint after file round trip: {:?}",
        vmctx.concolic.events
    );
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
