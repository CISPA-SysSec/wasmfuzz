#!/usr/bin/env bash
set -e
target="$1"
name=`basename $1`

source prepare-wasm2c-fuzzer.sh "$1"

export AFL_LLVM_CMPLOG=1

afl-clang-fast -O2 -g -o "$name-fuzzer" $CC_CMD

export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_AFFINITY=1

export AFL_BENCH_UNTIL_CRASH=1

function sync() {
    while true; do
        rsync -r /sync/default/queue/ /corpus/  --exclude=".state"
        rsync -r /sync/default/crashes/ /corpus/  --exclude="README.txt"
        sleep 5
    done
}
mkdir -p /sync/
sync &

afl-fuzz -G 4096 -i /seeds -o /sync -M default -c "./$name-fuzzer" -- "./$name-fuzzer" &
pids["1"]=$!
for i in $(seq 2 "${FUZZER_CORES:-1}")
do 
    afl-fuzz -G 4096 -i /seeds -o /sync -S "core-$i" -c "./$name-fuzzer" -- "./$name-fuzzer" > /dev/null &
    pids[${i}]=$!
done
for pid in ${pids[*]}; do
    wait $pid
done

rsync -r /sync/default/queue/ /corpus/  --exclude=".state"
rsync -r /sync/default/crashes/ /corpus/  --exclude="README.txt"