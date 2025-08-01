#!/bin/bash

if [ "$(ls -A '/out/')" ]; then
    file-rename 's/_fuzzer//' /out/*
    file-rename 's/-fuzzer//' /out/*
fi

if [ "$BUILD_TYPE" = "x86_64-libfuzzer" ]; then
    exit 0
fi

for module in /out/*.wasm;
do
    chmod -x "$module"
    # inject build-id
    # wasm-split -q "$module"
    # # bundle source files to /out/$module-src.zip
    # sentry-cli debug-files bundle-sources "$module"
    # # pretty output
    # sentry-cli debug-files check "$module"

    if [ -f /git-metadata.csv ]; then
        /wasi-sdk/bin/llvm-objcopy --add-section \
            "git-metadata.csv=/git-metadata.csv" "$module"
    fi
done
