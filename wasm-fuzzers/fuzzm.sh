#!/usr/bin/env bash
set -e

target="$1"
name=`basename $1`

#export AFL_SKIP_BIN_CHECK=1
#export __AFL_PERSISTENT=1 __AFL_SHM_FUZZ=1 AFL_FORKSRV_INIT_TMOUT=9999999
export WASM_MODE=1


shim-for-wafl.sh "$target" "/tmp/$name-wafl.wasm"

# instrument for fuzzm
afl_branch "/tmp/$name-wafl.wasm" "/tmp/$name-cov.wasm"
chmod +x /tmp/$name-cov.wasm

export AFL_MEMLIMIT_OPTS=" " # The AFL version is too old and doesn't support -G
run-afl-fuzz.sh "/tmp/$name-cov.wasm"
