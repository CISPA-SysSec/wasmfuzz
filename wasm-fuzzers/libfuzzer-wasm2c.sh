#!/usr/bin/env bash
set -e
target="$1"
name=`basename $1`

source prepare-wasm2c-fuzzer.sh "$1"

clang -O2 -fsanitize=fuzzer -g -o "$name-libfuzzer" $CC_CMD

mkdir -p /corpus/

"./$name-fuzzer" -fork="${FUZZER_CORES:-1}" -ignore_crashes=1 -ignore_timeouts=1 /corpus/ -artifact_prefix=/corpus/