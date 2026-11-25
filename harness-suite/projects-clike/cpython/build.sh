#!/bin/bash
set -e +x

cd "$PROJECT/repo"

# A build Python of the same version is required to cross-compile (freezing,
# deepfreeze, sysconfig). Build it natively before the wasm flags are set.
mkdir -p cross-build/build
(cd cross-build/build && ../../configure -q --disable-test-modules && make -j"$(nproc)")

source set-buildflags.sh
# wasi-sdk's LTO libc leaves __libc_calloc unresolved here (as for libxml2).
export CFLAGS="${CFLAGS/-flto=thin /}"
export AR="$WASI_SDK_PREFIX/bin/llvm-ar" RANLIB="$WASI_SDK_PREFIX/bin/llvm-ranlib"

# Configure as Platforms/WASI does, minus PY_CALL_TRAMPOLINE (it needs the
# wasm GC proposal); HOSTRUNNER is required but nothing is run.
mkdir -p cross-build/wasm32-wasip1
cd cross-build/wasm32-wasip1
CONFIG_SITE="$PROJECT/repo/Platforms/WASI/config.site-wasm32-wasi" HOSTRUNNER=false \
PKG_CONFIG_PATH= PKG_CONFIG_LIBDIR="$WASI_SDK_PREFIX/share/wasi-sysroot/lib/pkgconfig" \
    ../../configure --host=wasm32-wasip1 --build="$(../../config.guess)" \
        --with-build-python="$PWD/../build/python" \
        --disable-test-modules --without-ensurepip

FUZZERS="fuzz_pycompile fuzz_pycompile_source"
make -j"$(nproc)" -f Makefile -f "$PROJECT/fuzz.mk" FUZZ_LDFLAGS="$FUZZ_LDFLAGS" \
    $(for F in $FUZZERS; do echo fuzz-$F.wasm; done)
for F in $FUZZERS; do
    cp fuzz-$F.wasm /out/cpython-$F.wasm
done
