#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"
python3 scripts/config.py baremetal
python3 scripts/config.py set MBEDTLS_SSL_PROTO_DTLS
python3 scripts/config.py set MBEDTLS_SSL_CLI_C
# fuzz_dtls{client,server} compile to no-ops without MBEDTLS_TIMING_C (baremetal drops it).
# timing.c needs MBEDTLS_HAVE_TIME for mbedtls_ms_time() (port-wasi-time-entropy.patch); wasmfuzz's
# clock_time_get counts fuel, so DTLS retransmission timers stay deterministic.
python3 scripts/config.py set MBEDTLS_HAVE_TIME
python3 scripts/config.py set MBEDTLS_TIMING_C

make -C programs fuzz -j6 # make -j30 blows up :/

FUZZERS=$(find programs/fuzz/ -executable -iname "fuzz_*" -printf "%f\n")
for F in $FUZZERS; do
    cp programs/fuzz/$F /out/mbedtls-$F.wasm
done
