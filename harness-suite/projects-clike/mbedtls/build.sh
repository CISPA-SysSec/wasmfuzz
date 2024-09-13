#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

python3 scripts/config.py baremetal
python3 scripts/config.py set MBEDTLS_SSL_PROTO_DTLS
python3 scripts/config.py set MBEDTLS_SSL_CLI_C
python3 scripts/config.py set MBEDTLS_ENTROPY_C
python3 scripts/config.py set MBEDTLS_CTR_DRBG_C
python3 scripts/config.py set MBEDTLS_TIMING_C
python3 scripts/config.py set MBEDTLS_HAVE_TIME
python3 scripts/config.py set MBEDTLS_PLATFORM_TIME_ALT
python3 scripts/config.py set MBEDTLS_PLATFORM_MS_TIME_ALT
python3 scripts/config.py unset MBEDTLS_NO_PLATFORM_ENTROPY

make -C programs fuzz -j6 # make -j30 blows up :/

FUZZERS=$(find programs/fuzz/ -executable -iname "fuzz_*" -printf "%f\n")
for F in $FUZZERS; do
    cp programs/fuzz/$F /out/mbedtls_$F.wasm
done
