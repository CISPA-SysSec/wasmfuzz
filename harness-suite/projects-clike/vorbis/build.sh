#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

WORK=/tmp/

pushd $PROJECT/ogg
./autogen.sh
./configure $CONFIGUREFLAGS --prefix="$WORK" --enable-static --disable-shared --disable-crc
make clean
make -j$(nproc)
make install
popd



./autogen.sh
./configure $CONFIGUREFLAGS --prefix="$WORK" --enable-static --disable-shared
make clean
make -j$(nproc)
make install


$CXX $CXXFLAGS \
  contrib/oss-fuzz/decode_fuzzer.cc -o /out/vorbis-decode_fuzzer.wasm \
  -L"$WORK/lib" -I"$WORK/include" $LIB_FUZZING_ENGINE -lvorbisfile -lvorbis -logg

# build brotli_decode_fuzzer
#$CC $CFLAGS -std=c99 -I. -I./c/include \
#    c/fuzz/decode_fuzzer.c ./libbrotlidec.a ./libbrotlicommon.a \
#    $LIB_FUZZING_ENGINE \
#    -o /out/brotli-decode_fuzzer.wasm
