#!/usr/bin/env bash
set -e
target="$1"
name=`basename $1`

source prepare-w2c2-fuzzer.sh "$1"

AFL_LLVM_CMPLOG=1 afl-clang-fast -O2 -g -o "$name-fuzzer" $CC_CMD

run-afl-fuzz.sh -c "./$name-fuzzer" -- "./$name-fuzzer"