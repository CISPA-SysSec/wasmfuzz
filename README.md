<div align="center">
  <h1><code>wasmfuzz</code>: WebAssembly as a Fuzzing Compilation Target</h1>

  <p>A reasonablely good fuzzer for <code>libfuzzer</code>-style WebAssembly harnesses <br/>
    and a suite of C/C++/Rust projects for WASM fuzzer evals.</p>

  <p>

[![License](https://img.shields.io/github/license/cispa-syssec/wasmfuzz)](./LICENSE-APACHE)
[![Paper](https://img.shields.io/badge/paper-pdf-brightgreen)](./assets/isstaws24fuzzingmain-p5-p-30a9e696b6-80430-final.pdf)
[![DOI](https://img.shields.io/badge/doi-10.1145/3678722.3685531-blue)](https://doi.org/10.1145/3678722.3685531)
    
  </p>
</div>

![Overview Sketch](./assets/afl++-vs-wasmfuzz.svg#gh-light-mode-only)
![Overview Sketch](./assets/afl++-vs-wasmfuzz-dark.svg#gh-dark-mode-only)


## `wasmfuzz` Fuzzer

Our WebAssembly fuzzer prototype builds on LibAFL and a custom WASM JIT.
We insert instrumentation during the fuzzing campaign, and thus can run different combinations of feedback kinds on-demand.

`wasmfuzz` implements fast reset and runs harnesses that are designed for `libfuzzer`'s persistent mode APIs.
Compatible modules export `LLVMFuzzerTestOneInput` and `malloc` in order to be able to allocate space for the input data and run each fuzz case. Our implementation resets the module's state after each execution.

Based on a preliminary experiment comparing `wasmfuzz` and `cargo-fuzz` (libfuzzer), fuzzing efficacy should be on-par with native fuzzers.

### Installation

`wasmfuzz` currently requires Linux hosts for its snapshot-restore mechanism.

To build form source you need a somewhat recent stable or nightly Rust toolchain.

- From source: `cargo install --locked --force --git https://github.com/CISPA-SysSec/wasmfuzz`
- From a git checkout: `cargo install --locked --force --path .`
- Pre-built binaries: https://github.com/CISPA-SysSec/wasmfuzz/releases/download/initial-commit/wasmfuzz-x86_64-unknown-linux-gnu.2.31

Pre-built binaries are dynamically linked against an old `glibc` version (2.31) and should be compatible with most Linux environments.


### Usage Examples

Run a simple fuzzing campaign:
`wasmfuzz fuzz --timeout=1h --cores 8 --dir corpus/ the-module.wasm`

Create a line coverage report:
`wasmfuzz cov-html --corpus corpus/ --output report/ the-module.wasm`

Other options are available via `wasmfuzz --help` and `wasmfuzz fuzz --help`.


### Implementation Details

- Custom WebAssembly JIT with the [Cranelift](https://cranelift.dev/) code generator as its backend.
- Input mutation is handled by [LibAFL](https://crates.io/crates/libafl).
- Fully deterministic execution with fast-ish snapshot restore via CoW memory mappings.
- Pluggable instrumentation passes that can be configured on-the-fly.
- Simple ensemble fuzzing strategy that periodically swaps out instrumentation options.
- Coverage visualization via DWARF line debug information and DWARFv5 Embedded Source Code. We adapt [Coverage.py](https://github.com/nedbat/coveragepy)'s HTML template for our reports.

#### Instrumentation Passes

- Function-level, basic-block-level, edge-level code coverage: `src/instrumentation/code_coverage.rs`
- Arithmetic comparison distance coverage: `src/instrumentation/cmpcov.rs`
- Function all parameters and return values: `src/instrumentation/call_params.rs`
- Path coverage: `src/instrumentation/path_hash.rs`
- Function / loop hitcounts: `src/instrumentation/perffuzz.rs`
- Execution trace instruction limits: `src/instrumentation/instruction_limit.rs`
- Memory access values, pointer ranges: `src/instrumentation/mem.rs`
- Shortest input that reaches each function / basic block: `src/instrumentation/input_size.rs`

Note: We have not evaluated the effectiveness of these passes yet.

#### Current Limitations

- Exits if a crash is found
- No core pinning
- Does not support LibAFL-style network scaling (we use simple ad-hoc in-process message passing and structure sharing, no `llmp`)
- No support for the WebAssembly 2.0 _Component Model_.

## Harness Suite ([./harness-suite/](./harness-suite/))

Building these requires a Docker/Podman and Python installation. Use `make -C harness-suite` to build all projects.

- Standard `libfuzzer`-compatible harness API (`LLVMFuzzerTestOneInput`).

- Mix of C/C++ and Rust targets. C/C++ projects require porting while Rust targets have drop-in support.

- Currently builds 18 C/C++ and 29 Rust projects. This includes 6 out of the 19 [fuzzbench targets](https://github.com/google/fuzzbench/tree/e72f5bb91bfafd98752fff29e3a961494b85a321/benchmarks) at the moment.

- Optimized builds with full debug info: Harness modules also contain their source code so we can emit coverage reports without any additional files.

We target the [Lime1](https://github.com/WebAssembly/tool-conventions/blob/main/Lime.md#lime1) series of WebAssembly, which is WebAssembly 1.0 in combination with a few standardized post-1.0 features like the `bulk-memory-opt` extension.


## WASM Variants of Other Fuzzers ([./wasm-fuzzers/](./wasm-fuzzers/))

We retrofit support for WebAssembly to native fuzzers via a KISS recompilation strategy:
`wasm2c` translates WASM modules to plain C files, which we then run through standard source-level fuzzing setups.

Currently, we include the following fuzzers in our evaluation scripts:
- `wasmfuzz`
- [WAFL](https://github.com/fgsect/WAFL) (a WASM harness fuzzer, adapted for libfuzzer harnesses)
- libfuzzer-wasm2c
- aflpp-wasm2c
- libafl\_libfuzzer-wasm2c

### Limitations

Symbols get renamed during the wasm2c process for native fuzzers. Due to this, hardcoded support for input-to-state mutations might be impacted due to symbol names and/or non-standard unrolled translated implementations.
We have not confirmed the impact of this specific issue though.


## Notes on Upstreaming

- Our JIT currently depends on a minor patch to Cranelift's JIT setup: [[Upstream PR]](https://github.com/bytecodealliance/wasmtime/pull/10512)

- `rustc` support for `-Zembed-source` for embedded sources in harness binaries: [[Upstream PR]](https://github.com/rust-lang/rust/pull/126985)

- `symbolic` only supports DWARF embedded sources at exactly v12.10.0-v12.11.1: [[Upstream PR]](https://github.com/getsentry/symbolic/pull/849)

#### Fuzzer Integration

- We're using a patched version of WAFL that side-steps a crash when using WASM modules that have symbols: [[Upstream PR]](https://github.com/fgsect/WAFL/pull/10)

- We have applied several patches to FuzzM in order to be able to run our WASM modules:
    * Wasmtime: Avoid assertion failure in `raw-cpuid` crate: [fuzzm-wasmtime-0.20-fix-cpuid.patch](wasm-fuzzers/fuzzm-wasmtime-0.20-fix-cpuid.patch)
    * Wasabi: Support the Lime1 extensions by @doehyunbaek [[Upstream PR]](https://github.com/danleh/wasabi/pull/41)
    * Wasabi: Fix parser error with overlong `call_indirect` encoding [[Upstream PR]](https://github.com/doehyunbaek/wasabi/pull/1)
    * FuzzM: Adjust for Wasabi changes [[Upstream PR]](https://github.com/fuzzm/fuzzm-project/pull/6)

