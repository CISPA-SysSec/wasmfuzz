#!/bin/bash
set -e +x
source set-buildflags.sh
cd "$PROJECT/repo"
build-rust-harness.py