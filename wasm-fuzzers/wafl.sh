#!/usr/bin/env bash
set -e

target="$1"
name=`basename $1`

export AFL_SKIP_BIN_CHECK=1
export __AFL_PERSISTENT=1 __AFL_SHM_FUZZ=1 AFL_FORKSRV_INIT_TMOUT=9999999

shim-for-wafl.sh "$target" "/tmp/$name-wafl.wasm"

run-afl-fuzz.sh wavm run "/tmp/$name-wafl.wasm"
