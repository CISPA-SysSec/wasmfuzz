#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"


# Build the library.
mkdir build
cd build
# Note: We disable `cmark-fuzz.c` since it isn't maintained doesn't build
cmake .. -DBUILD_SHARED_LIBS=OFF \
  -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
  -DCMARK_TESTS=OFF -DCMARK_SHARED=OFF \
  -DCMARK_LIB_FUZZER=OFF -DCMARK_FUZZ_QUADRATIC=ON
make -j $(nproc)

cp ./fuzz/fuzz_quadratic /out/cmark-gfm-fuzz-quadratic.wasm
cp ./fuzz/fuzz_quadratic_brackets /out/cmark-gfm-fuzz-quadratic-brackets.wasm

#$CC $CFLAGS $LIB_FUZZING_ENGINE \
#  -Isrc -Ibuild/src \
#  src/libcmark.a fuzz/cmark-fuzz.c \
#  -o /out/cmark-gfm_fuzzer.wasm
# $CXX $CXXFLAGS $LIB_FUZZING_ENGINE cmark_fuzzer.o build/src/libcmark.a -o $OUT/cmark-gfm-fuzzer.wasm
