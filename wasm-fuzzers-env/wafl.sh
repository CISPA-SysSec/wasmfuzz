#!/usr/bin/env bash
set -e

target="$1"
name=`basename $1`

export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_BIN_CHECK=1
export __AFL_PERSISTENT=1 __AFL_SHM_FUZZ=1 AFL_FORKSRV_INIT_TMOUT=9999999
export AFL_NO_AFFINITY=1

shim-for-wafl.sh "$target" "/tmp/$name-wafl.wasm"

export AFL_BENCH_UNTIL_CRASH=1

function sync() {
    while true; do
        rsync -r /sync/default/queue/ /corpus/  --exclude=".state"
        rsync -r /sync/default/crashes/ /corpus/  --exclude="README.txt"
        sleep 30
    done
}
mkdir -p /sync/
sync &


afl-fuzz -G 4096 -i /seeds -o /sync -M default wavm run "/tmp/$name-wafl.wasm" &
pids["1"]=$!
for i in $(seq 2 "${FUZZER_CORES:-1}")
do 
    afl-fuzz -G 4096 -i /seeds -o /sync -S "core-$i" wavm run "/tmp/$name-wafl.wasm" > /dev/null &
    pids[${i}]=$!
done
for pid in ${pids[*]}; do
    wait $pid
done

rsync -r /sync/default/queue/ /corpus/  --exclude=".state"
rsync -r /sync/default/crashes/ /corpus/  --exclude="README.txt"