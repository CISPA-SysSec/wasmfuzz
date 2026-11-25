#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# mirrors tests/ossfuzz.sh (oss-fuzz projects/stb/build.sh runs it)
$CXX $CXXFLAGS -std=c++11 -I. -DSTBI_ONLY_PNG \
    ./tests/local_fuzz/image.c \
    -o /out/stb-png_read_fuzzer.wasm $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -I. \
    ./tests/local_fuzz/image.c \
    -o /out/stb-stbi_read_fuzzer.wasm $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -I. \
    ./tests/local_fuzz/vorbis.c \
    -o /out/stb-vorbis_fuzzer.wasm $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -I. \
    ./tests/local_fuzz/c_lexer.c \
    -o /out/stb-c_lexer_fuzzer.wasm $LIB_FUZZING_ENGINE
