#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"
make clean
make
mkdir -p ./out/
make install DEST=./out/

for fuzzer in ./out/*_fuzzer; do
    cp $fuzzer /out/lzma-$(basename "$fuzzer").wasm
done
