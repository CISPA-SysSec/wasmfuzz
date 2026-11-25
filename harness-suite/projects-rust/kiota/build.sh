#!/bin/bash
set -e +x
source set-buildflags.sh
# The checker recurses deeply (kiota's CLI checks on a 1 GiB-stack thread).
build-rust-harness.py --large-stack
