#!/bin/bash
set -e +x
source set-buildflags.sh

export CFLAGS="$CFLAGS -DHB_NO_VISIBILITY -DHB_NO_MMAP"
export CXXFLAGS="$CXXFLAGS -DHB_NO_VISIBILITY -DHB_NO_MMAP"

cd "$PROJECT/repo"

meson setup build \
    --cross-file "$PROJECT/wasi-lime1.cross" \
    --default-library=static \
    --wrap-mode=nodownload \
    -Dexperimental_api=true \
    -Dfuzzer_ldflags="$LIB_FUZZING_ENGINE" \
    -Dfreetype=disabled \
    -Dglib=disabled \
    -Dgobject=disabled \
    -Dcairo=disabled \
    -Dchafa=disabled \
    -Dicu=disabled \
    -Dgraphite2=disabled \
    -Dpng=disabled \
    -Dzlib=disabled \
    -Draster=disabled \
    -Dvector=disabled \
    -Dgpu=disabled \
    -Dsubset=disabled \
    -Dutilities=disabled \
    -Dbenchmark=disabled \
    -Ddocs=disabled \
    -Dc_args="$CFLAGS" \
    -Dc_link_args="$CFLAGS" \
    -Dcpp_args="$CXXFLAGS" \
    -Dcpp_link_args="$CXXFLAGS"

ninja -C build src/libharfbuzz.a

# Meson links fuzz targets with GNU ld flags (--start-group, --as-needed, …)
# that wasm-ld does not accept; link the harness manually instead.
$CXX $CXXFLAGS \
    -DHB_IS_IN_FUZZER -DHB_EXPERIMENTAL_API \
    -I. -Ibuild -Isrc -Itest/fuzzing \
    test/fuzzing/hb-shape-fuzzer.cc \
    build/src/libharfbuzz.a \
    $LIB_FUZZING_ENGINE \
    -o /out/harfbuzz-hb-shape-fuzzer.wasm
