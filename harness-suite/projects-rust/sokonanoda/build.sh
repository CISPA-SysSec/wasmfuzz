#!/bin/bash
set -e +x
source set-buildflags.sh
# The checker recurses deeply (sokonanoda runs its checker threads on 2 GiB stacks).
build-rust-harness.py --large-stack
