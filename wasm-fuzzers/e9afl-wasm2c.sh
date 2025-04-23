#!/usr/bin/env bash
set -e
set -x
target="$1"
name=`basename $1`

# FIXME: this should use a persistent-mode main? does e9afl support this use-case?
source prepare-wasm2c-fuzzer.sh "$1"
afl-clang-fast -O2 -g -o "$name-fuzzer" $CC_CMD
e9afl "$name-fuzzer"
export AFL_MEMLIMIT_OPTS=" " # The AFL version is too old and doesn't support -G
run-afl-fuzz.sh -- "./$name-fuzzer.afl"
