#!/bin/bash
set -e +x
source set-buildflags.sh
# The value kernel recurses natively (kefir-wasm runs on a 2 GiB engine stack).
build-rust-harness.py --large-stack
