#!/usr/bin/env bash
set -e

target="$1"

if [ "$FUZZER_CONFIG" == "zoo" ]; then
    wasmfuzz fuzz-zoo --seed-dir=/seeds/ --out-dir=/corpus/ "$target" $FUZZER_ARGS
elif [[ "$FUZZER_CONFIG" =~ ^orc- ]]; then
    cores=${FUZZER_CONFIG#"orc-"}
    wasmfuzz fuzz-orc --seed-dir=/seeds/ --out-dir=/corpus/ "$target" --cores="$cores" $FUZZER_ARGS
elif [[ "$FUZZER_CONFIG" =~ ^pass- ]]; then
    pass=${FUZZER_CONFIG#"pass-"}
    wasmfuzz fuzz --seed-dir=/seeds/ --out-dir=/corpus/ "$target" \
        --trap-cmpcov-hamming=false \
        --trap-cmpcov-absdist=false \
        --trap-func-perffuzz=false \
        --trap-func-input-size=false \
        "--trap-$pass=true"
else
    wasmfuzz fuzz-orc "$1" \
        --seed-dir=/seeds/ --out-dir=/corpus/ \
        --cores="${FUZZER_CORES:-1}" \
        $FUZZER_ARGS
fi
