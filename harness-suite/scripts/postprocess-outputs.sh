#!/bin/bash

file-rename 's/_fuzzer//' /out/*.wasm
file-rename 's/-fuzzer//' /out/*.wasm

for module in /out/*.wasm;
do
    chmod -x "$module"
    # inject build-id
    wasm-split -q "$module"
    # # bundle source files to /out/$module-src.zip
    # sentry-cli debug-files bundle-sources "$module"
    # # pretty output
    # sentry-cli debug-files check "$module"

    if [ -f /git-metadata.csv ]; then
        /wasi-sdk/bin/llvm-objcopy --add-section \
            "git-metadata.csv=/git-metadata.csv" "$module"
    fi
done
