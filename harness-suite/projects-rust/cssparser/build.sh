#!/bin/bash
set -e +x
source set-buildflags.sh
# Builds both the upstream harness (repo/fuzz: tokenizer round-trip) and our
# additional harnesses in fuzz/ (rule/declaration lists, An+B, colors, selectors).
build-rust-harness.py
