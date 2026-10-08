#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Mirrors oss-fuzz/projects/nestegg/build.sh (upstream test/fuzz.cc harness).
$CC $CFLAGS -c -I./include src/nestegg.c -o nestegg.o
$CXX $CXXFLAGS -I./include test/fuzz.cc nestegg.o \
  -o /out/nestegg-fuzz.wasm $LIB_FUZZING_ENGINE
