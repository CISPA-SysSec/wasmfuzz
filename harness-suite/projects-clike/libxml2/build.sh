#!/bin/bash
set -e +x
source set-buildflags.sh


# Note: LTO support is somewhat broken as of wasi-sdk 25. Linking fails with a
# missing __libc_calloc symbol error for this particular target.
export CFLAGS="${CFLAGS/-flto=thin /}"

cd "$PROJECT/repo"

export V=1

./autogen.sh \
    --disable-shared \
    --without-debug \
    --without-threads \
    --without-http \
    --without-python \
    --without-zlib --without-lzma \
    --host=wasm32-wasi
make -j$(nproc)

FUZZERS="html regexp schema uri valid xinclude xml xpath"

cd fuzz
make clean-corpus
make fuzz.o
for F in $FUZZERS; do
    make $F.o

    $CC $CCFLAGS \
        $F.o fuzz.o \
        -o /out/libxml2-$F.wasm \
        $LIB_FUZZING_ENGINE \
        ../.libs/libxml2.a -Wl,-Bstatic -Wl,-Bdynamic
done
