#!/bin/bash
set -e
# upstream HEAD; Firefox ships 503d81b138 (media/libopus/moz.yaml), Chromium 55513e81.
git clone-rev.sh https://gitlab.xiph.org/xiph/opus.git "$PROJECT/repo" 503d81b138d76621aae4b12786e90de48aa8db3a
# Decoder-side harnesses from oss-fuzz/projects/opus (the upstream-maintained
# opus_decode_fuzzer.c already lives in tests/).
cp "$PROJECT"/opus_*_fuzzer.cc "$PROJECT"/opus_ossfuzz_utils.h "$PROJECT/repo/tests/"
# autogen.sh also downloads the DNN model, which is only needed for
# DRED/deep-PLC/OSCE (all disabled, as in Chromium and Firefox).
cd "$PROJECT/repo" && autoreconf -isf
