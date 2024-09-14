#!/usr/bin/env bash
set -e
target="$1"
name=`basename $1`

source prepare-wasm2c-fuzzer.sh "$1"

clang -c -fsanitize=fuzzer-no-link -O2 -g $CC_CMD
clang++ -fsanitize=fuzzer-no-link -L/LibAFL/libafl_libfuzzer/libafl_libfuzzer_runtime/ -lFuzzer \
  wasm-rt-impl.o wasm2c-harness.o wasm2c-wrapper.o \
  -lm -o "$name-fuzzer"

mkdir -p /corpus/

if [ "$FUZZER_CONFIG" == "multicore" ]; then
  "./$name-fuzzer" -fork=8  -ignore_crashes=1 -ignore_timeouts=1 /corpus/ -grimoire=0 -artifact_prefix=/corpus/
else
  "./$name-fuzzer" -fork=1 -ignore_crashes=1 -ignore_timeouts=1 /corpus/ -grimoire=0 -artifact_prefix=/corpus/
fi
