#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"


# Modify AR flags as "f" is not a valid option to llvm-ar.
sed -i 's/crf/cr/g' Makefile

# woff2 uses LFLAGS instead of LDFLAGS.
make clean
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= NOISY_LOGGING= \
  convert_woff2ttf_fuzzer convert_woff2ttf_fuzzer_new_entry
# make all should work, but we're only building the fuzzers
# as a workaround for an wasi-sdk stdc++ fstream issue

# Build fuzzers
for fuzzer_archive in src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer_archive \
      -o /out/woff2-$fuzzer_name.wasm
  # zip -q $OUT/${fuzzer_name}_seed_corpus.zip $SRC/corpus/*
done