#!/bin/bash
set -e +x
source set-buildflags.sh
# The checker recurses deeply (natively its main runs on a 256 MiB thread).
build-rust-harness.py --large-stack
