#!/bin/bash
set -e +x
source set-buildflags.sh


# TODO: not sure why flto breaks stuff for this particular target
export CFLAGS="${CFLAGS/-flto /}"

cd "$PROJECT/repo"

export V=1

./autogen.sh \
    --disable-shared \
    --without-debug \
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
        -o /out/libxml2_$F.wasm \
        $LIB_FUZZING_ENGINE \
        ../.libs/libxml2.a -Wl,-Bstatic -Wl,-Bdynamic
done
