#!/bin/bash
set -e +x
source set-buildflags.sh
# The checker recurses deeply (con-ron runs its workers on 1 GiB stacks).
build-rust-harness.py --large-stack
