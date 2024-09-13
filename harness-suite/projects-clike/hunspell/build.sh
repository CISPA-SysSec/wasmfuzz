#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

autoreconf -vfi
./configure --host=wasm32-wasi --disable-shared --enable-static

make clean
make config.h && make -C src/hunspell -j libhunspell-1.7.la


#$CXX $CXXFLAGS -o /out/hunspell-fuzzer.wasm -I./src/ \
#    $LIB_FUZZING_ENGINE \
#    ./src/tools/fuzzer.cxx ./src/hunspell/.libs/libhunspell-1.7.a
# cp -f ./src/tools/fuzzer.options $OUT/
$CXX $CXXFLAGS -o /out/hunspell-affdicfuzzer.wasm -I./src/ \
    $LIB_FUZZING_ENGINE \
    ./src/tools/affdicfuzzer.cxx ./src/hunspell/.libs/libhunspell-1.7.a

##dic/aff combos to test
#cp -f ./tests/arabic.* $OUT/
#cp -f ./tests/checkcompoundpattern*.* $OUT/
#cp -f ./tests/korean.* $OUT/
#cp -f ./tests/utf8*.* $OUT/
