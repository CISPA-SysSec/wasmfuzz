#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo/ogg"

./autogen.sh
./configure $CONFIGUREFLAGS --enable-static --disable-shared --disable-crc
make clean
make -j7
make install

cd "$PROJECT/repo"

./autogen.sh
./configure $CONFIGUREFLAGS --enable-static --disable-shared
make clean
make -j7
make install

$CXX $CXXFLAGS \
  contrib/oss-fuzz/decode_fuzzer.cc -o /out/vorbis-decode_fuzzer.wasm \
  -I include/ -I ogg/include/ \
  $LIB_FUZZING_ENGINE lib/.libs/libvorbis{,file}.a ogg/src/.libs/libogg.a
