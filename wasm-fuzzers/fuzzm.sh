#!/usr/bin/env bash
set -e

target="$1"
name=`basename $1`

export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_BIN_CHECK=1
export __AFL_PERSISTENT=1 __AFL_SHM_FUZZ=1 AFL_FORKSRV_INIT_TMOUT=9999999
export AFL_NO_AFFINITY=1


export WASM_MODE=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1



# instrument for fuzzm
afl_branch "$target" "/tmp/$name-cov.wasm"

# LD_LIBRARY_PATH=../AFL-wasm/wasmtime-v0.20.0-x86_64-linux-c-api/lib/ ../public-project-repo/fuzzm-project/AFL-wasm/afl-fuzz -i testcases/ -o findings ./vuln-cov-canaries.wasm


# shim-for-wafl.sh "$target" "/tmp/$name-wafl.wasm"

function sync() {
    while true; do
        rsync -r /sync/default/queue/ /corpus/  --exclude=".state"
        sleep 5
    done
}
mkdir -p /sync/
sync &


# LD_LIBRARY_PATH=../AFL-wasm/wasmtime-v0.20.0-x86_64-linux-c-api/lib/ ../public-project-repo/fuzzm-project/AFL-wasm/afl-fuzz -i testcases/ -o findings ./vuln-cov-canaries.wasm


if [ "$FUZZER_CONFIG" == "multicore" ]; then
    afl-fuzz -G 4096 -i /seeds -o /sync -M default "/tmp/$name-cov.wasm" &
    pids["1"]=$!
    for i in {2..8}
    do 
        afl-fuzz -G 4096 -i /seeds -o /sync -S "core-$i" "/tmp/$name-cov.wasm" > /dev/null &
        pids[${i}]=$!
    done
    for pid in ${pids[*]}; do
        wait $pid
    done
else
    afl-fuzz -G 4096 -i /seeds -o /sync "/tmp/$name-cov.wasm"
fi
