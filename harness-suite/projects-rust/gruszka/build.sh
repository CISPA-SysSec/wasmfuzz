#!/bin/bash
set -e +x
source set-buildflags.sh
# The checker recurses deeply (gruszka's workers run on 1 GiB stacks).
build-rust-harness.py --large-stack
