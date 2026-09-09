#!/bin/bash
set -e +x
source set-buildflags.sh
build-rust-harness.py

# decode_parallel's runner spawns threads via std::thread::scope, which
# wasm32-wasip1 does not support: any input that hands the runner more than one
# task aborts with "failed to spawn thread". Drop the harness.
rm -f /out/jxl-rs-decode_parallel.wasm
