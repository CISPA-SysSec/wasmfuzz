#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Chromium only compiles the GIF decoder (plus LZW and base CORE/INTERFACES/
# PIXCONV) out of Wuffs (third_party/wuffs/BUILD.gn, use_wuffs_gif_parser).
# gif_fuzzer covers GIF+LZW; pixel_swizzler_fuzzer covers base PIXCONV, which
# SkWuffsCodec uses to convert decoded frames. At the v0.4 HEAD built here,
# pixel_swizzler_fuzzer also fuzzes swizzle_ycck (JPEG YCbCr/YCCK conversion),
# which is not in the v0.3 code Chromium ships.
for b in gif pixel_swizzler; do
    $CC $CFLAGS -c fuzz/c/std/${b}_fuzzer.c -o /tmp/${b}_fuzzer.o
    $CXX $CXXFLAGS /tmp/${b}_fuzzer.o -o /out/wuffs-${b}_fuzzer.wasm $LIB_FUZZING_ENGINE
done
