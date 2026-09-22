#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"
cp "$PROJECT"/oss-fuzz/projects/lcms/*.c .

autoreconf -f -i
./configure --without-threads --enable-shared=no $CONFIGUREFLAGS
make all

FUZZERS="cms_transform_fuzzer           \
        cms_overwrite_transform_fuzzer \
        cms_transform_all_fuzzer       \
        cms_universal_transform_fuzzer \
        cms_transform_extended_fuzzer  \
        cmsIT8_load_fuzzer             \
        cms_profile_fuzzer"

for F in $FUZZERS; do
    $CC $CFLAGS -Iinclude \
        -D_WASI_EMULATED_GETPID \
        $F.c src/.libs/liblcms2.a \
        $LIB_FUZZING_ENGINE -lwasi-emulated-getpid \
        -o "/out/lcms-$F.wasm"
done
