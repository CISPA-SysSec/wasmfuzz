#!/bin/bash
set -e +x
source set-buildflags.sh
# Harnesses live in $PROJECT/fuzz (upstream has no fuzz/ directory); the repo's
# own Cargo.toml has no cargo-fuzz metadata so only fuzz/ is built.
build-rust-harness.py
