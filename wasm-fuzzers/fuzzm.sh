#!/usr/bin/env bash
set -e

target="$1"
name=`basename $1`

export AFL_SKIP_BIN_CHECK=1
export __AFL_PERSISTENT=1 __AFL_SHM_FUZZ=1 AFL_FORKSRV_INIT_TMOUT=9999999
export WASM_MODE=1



# instrument for fuzzm
afl_branch "$target" "/tmp/$name-cov.wasm"

# LD_LIBRARY_PATH=../AFL-wasm/wasmtime-v0.20.0-x86_64-linux-c-api/lib/ ../public-project-repo/fuzzm-project/AFL-wasm/afl-fuzz -i testcases/ -o findings ./vuln-cov-canaries.wasm


# shim-for-wafl.sh "$target" "/tmp/$name-wafl.wasm"

run-afl-fuzz.sh "/tmp/$name-cov.wasm"

