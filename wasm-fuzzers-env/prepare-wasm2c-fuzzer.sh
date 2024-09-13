#!/usr/bin/env bash
set -e

target="$1"
name=`basename $1`

wizer "$target" -o "/tmp/$name" \
    --allow-wasi --wasm-bulk-memory=true --init-func=_initialize \
    || cp "$target" "/tmp/$name"

wasm2c "/tmp/$name" -o wasm2c-harness.c -n harness

WRAPPER_DEFS=""
if grep -q "void Z_harness_instantiate.*Z_wasi_snapshot_preview1_instance_t" wasm2c-harness.h; then
  WRAPPER_DEFS="$WRAPPER_DEFS -DIMPORT_WASI"
fi
if grep -q "void Z_harness_instantiate.*Z_env_instance_t" wasm2c-harness.h; then
  WRAPPER_DEFS="$WRAPPER_DEFS -DIMPORT_ENV"
fi
MODULE_COUNT=`echo "$WRAPPER_DEFS" | grep -o "-" | wc -l`
WRAPPER_DEFS="$WRAPPER_DEFS -DMODULE_COUNT=$MODULE_COUNT"

export CC_CMD="-I /usr/share/wabt/wasm2c/ /usr/share/wabt/wasm2c/wasm-rt-impl.c wasm2c-wrapper.c wasm2c-harness.c -lm $WRAPPER_DEFS"