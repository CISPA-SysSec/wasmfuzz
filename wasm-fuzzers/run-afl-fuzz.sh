#!/usr/bin/env bash
set -e

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_AFFINITY=1
export AFL_BENCH_UNTIL_CRASH=1

function syncOne() {
    rsync -r /sync/default/queue/ /corpus/ --exclude=".state" --chmod=ugo=rwX
    rsync -r /sync/default/crashes/ /corpus/  --exclude="README.txt" --chmod=ugo=rwX
}
function syncForever() {
    while true; do
        syncOne; sleep 5
    done
}

mkdir -p /sync/
syncForever &

afl-fuzz -G 4096 -i /seeds -o /sync -M default $@ &
pids["1"]=$!
for i in $(seq 2 "${FUZZER_CORES:-1}")
do
    afl-fuzz -G 4096 -i /seeds -o /sync -S "core-$i" $@ > /dev/null &
    pids[${i}]=$!
done
for pid in ${pids[*]}; do
    wait $pid
done

syncOne
