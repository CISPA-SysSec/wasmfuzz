#!/usr/bin/env bash
set -e

target="$1"
name=`basename $1`

mkdir /tmp/harness
wizer "$target" -o /tmp/harness/harness.wasm \
    --allow-wasi --wasm-bulk-memory=true --init-func=_initialize \
    || cp "$target" /tmp/harness/harness.wasm

# w2c2 is a bit peculiar about the harness path and includes it in the generated code
/w2c2/build/w2c2/w2c2 /tmp/harness/harness.wasm harness.c

export CC_CMD="-I /w2c2/w2c2 -I /w2c2/wasi harness.c w2c2-wrapper.c -lm /w2c2/build/wasi/libw2c2wasi.a"
