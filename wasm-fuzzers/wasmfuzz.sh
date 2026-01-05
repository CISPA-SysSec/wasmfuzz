#!/usr/bin/env bash
set -e

target="$1"

if [[ "$FUZZER_CONFIG" =~ ^orc- ]]; then
    cores=${FUZZER_CONFIG#"orc-"}
    wasmfuzz fuzz --seed-dir=/seeds/ --out-dir=/corpus/ "$target" --cores="$cores" $FUZZER_ARGS
elif [[ "$FUZZER_CONFIG" =~ ^pass-old- ]]; then
    pass=${FUZZER_CONFIG#"pass-old-"}
    wasmfuzz fuzz --seed-dir=/seeds/ --out-dir=/corpus/ "$target" \
        --trap-cmpcov-hamming=false \
        --trap-cmpcov-absdist=false \
        --trap-func-perffuzz=false \
        --trap-func-input-size=false \
        "--trap-$pass=true" \
        --cores 1
elif [[ "$FUZZER_CONFIG" =~ ^pass-old- ]]; then
    exp=${FUZZER_CONFIG#"exp-"}
    wasmfuzz fuzz "$1" \
        --seed-dir=/seeds/ --out-dir=/corpus/ \
        --cores="${FUZZER_CORES:-1}" \
        --experiment "$exp" $FUZZER_ARGS
else
    wasmfuzz fuzz "$1" \
        --seed-dir=/seeds/ --out-dir=/corpus/ \
        --cores="${FUZZER_CORES:-1}" \
        $FUZZER_ARGS
fi
