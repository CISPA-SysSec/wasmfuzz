#!/bin/bash
set -e
# upstream HEAD; Firefox ships 503d81b138 (media/libopus/moz.yaml), Chromium 55513e81.
git clone-rev.sh https://gitlab.xiph.org/xiph/opus.git "$PROJECT/repo" 316c675fa1c9982d76e9cdcba7231076f75047da
# Decoder-side harnesses from oss-fuzz/projects/opus (the upstream-maintained
# opus_decode_fuzzer.c already lives in tests/).
cp "$PROJECT"/opus_*_fuzzer.cc "$PROJECT"/opus_ossfuzz_utils.h "$PROJECT/repo/tests/"
# autogen.sh also downloads the DNN model, which is only needed for
# DRED/deep-PLC/OSCE (all disabled, as in Chromium and Firefox).
cd "$PROJECT/repo" && autoreconf -isf
