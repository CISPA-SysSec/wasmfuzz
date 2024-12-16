#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

cat << EOF > pngusr.h
#define PNG_NO_SETJMP
#define PNG_NO_SIMPLIFIED_READ
#define PNG_NO_SIMPLIFIED_WRITE
EOF

# build libpng
autoreconf -f -i
CPPFLAGS="$CXXFLAGS -DPNG_USER_CONFIG" ./configure --disable-shared --host=wasm32-wasi
make libpng16.la
llvm-ranlib .libs/libpng16.a

# build libpng_read_fuzzer
$CXX $CXXFLAGS -std=c++11 -I. \
    contrib/oss-fuzz/libpng_read_fuzzer.cc .libs/libpng16.a \
    $LIB_FUZZING_ENGINE \
    -lz \
    -o /out/libpng-read_fuzzer.wasm
