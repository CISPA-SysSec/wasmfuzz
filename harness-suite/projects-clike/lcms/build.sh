#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

cp "$PROJECT"/oss-fuzz/projects/lcms/*.c .

# build libpng
autoreconf -f -i
./configure --enable-shared=no --host=wasm32-wasi
make all

# build your fuzzer(s)
FUZZERS="cms_transform_fuzzer           \
        cms_overwrite_transform_fuzzer \
        cms_transform_all_fuzzer       \
        cms_universal_transform_fuzzer \
        cms_transform_extended_fuzzer"

# these fuzzers require vfs emulation (`sprintf(filename, "/tmp/fuzzer-it.%d.it8", getpid());`)
DISABLED_FUZZERS="cmsIT8_load_fuzzer cms_profile_fuzzer"

for F in $FUZZERS; do
    $CC $CFLAGS -Iinclude \
        $F.c src/.libs/liblcms2.a \
        $LIB_FUZZING_ENGINE \
        -o "/out/$F.wasm"
done