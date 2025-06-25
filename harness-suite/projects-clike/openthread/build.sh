#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

set -euxo pipefail

(
    mkdir build
    cd build || exit

    cmake -GNinja -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
        -DCMAKE_C_FLAGS="${CFLAGS}" \
        -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
        -DOT_COMPILE_WARNING_AS_ERROR=ON \
        -DOT_FUZZ_TARGETS=ON \
        -DOT_MULTIPLE_INSTANCE=ON \
        -DOT_PLATFORM=nexus \
        -DOT_THREAD_VERSION=1.4 \
        -DOT_APP_CLI=OFF \
        -DOT_APP_NCP=OFF \
        -DOT_APP_RCP=OFF \
        -DOT_PROJECT_CONFIG=../tests/nexus/openthread-core-nexus-config.h \
        ..
    ninja -j7
)

find . -name '*-fuzzer' -exec cp -v '{}' "/out/" ';'

for x in /out/*; do
    mv $x "/out/openthread-$(basename $x).wasm";
done
