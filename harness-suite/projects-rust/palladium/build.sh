#!/bin/bash
set -e +x
source set-buildflags.sh
# The checker recurses deeply (palladium runs its workers on 256 MiB to 4 GiB stacks).
build-rust-harness.py --large-stack
