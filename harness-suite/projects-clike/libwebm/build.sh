#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Upstream harness testing/mkvparser_fuzzer.cc (built by CMake with ENABLE_FUZZING).
$CXX $CXXFLAGS -I. \
  testing/mkvparser_fuzzer.cc mkvparser/mkvparser.cc mkvparser/mkvreader.cc \
  -o /out/libwebm-mkvparser_fuzzer.wasm $LIB_FUZZING_ENGINE
