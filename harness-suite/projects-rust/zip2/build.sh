#!/bin/bash
set -e +x
source set-buildflags.sh
build-rust-harness.py --large-stack
