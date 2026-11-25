#!/bin/bash
set -e +x
source set-buildflags.sh
# The checkers recurse deeply (nl-fast runs them on 256 MiB stacks).
build-rust-harness.py --large-stack
