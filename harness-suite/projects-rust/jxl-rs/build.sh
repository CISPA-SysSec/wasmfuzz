#!/bin/bash
set -e +x
source set-buildflags.sh
build-rust-harness.py

# decode_parallel, decode_progressive_parallel and decode_diff hand the decoder
# a runner that spawns threads via std::thread::scope, which wasm32-wasip1 does
# not support: any input that hands the runner more than one task aborts with
# "failed to spawn thread" (decode_diff runs the decode again with two threads
# and compares, so it has nothing to compare against without them). Drop them.
rm -f /out/jxl-rs-decode_parallel.wasm /out/jxl-rs-decode_progressive_parallel.wasm /out/jxl-rs-decode_diff.wasm
