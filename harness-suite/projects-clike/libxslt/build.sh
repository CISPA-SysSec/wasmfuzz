#!/bin/bash
set -e +x
source set-buildflags.sh

# LTO is somewhat broken with wasi-sdk for libxml2 (see projects-clike/libxml2)
export CFLAGS="${CFLAGS/-flto=thin /}"
export CXXFLAGS="${CXXFLAGS/-flto=thin /}"
export V=1

# libxml2: mirror Chromium's configuration (third_party/libxml/chromium/roll.py),
# except: no threads (wasm), no ICU (not available; Chromium uses ICU for
# encoding conversion only).
cd "$PROJECT/libxml2"
./autogen.sh \
    --disable-shared \
    --with-html --with-output --with-push --with-reader --with-sax1 \
    --with-tree --with-writer --with-xpath \
    --without-threads --without-icu \
    --without-c14n --without-catalog --without-debug --without-http \
    --without-iconv --without-iso8859x --without-legacy --without-lzma \
    --without-modules --without-pattern --without-python --without-regexps \
    --without-schemas --without-schematron --without-valid --without-xinclude \
    --without-xptr --without-zlib --without-relaxng \
    --without-readline --without-history --without-tls --without-minimum \
    $CONFIGUREFLAGS
make -j$(nproc)

# libxslt: mirror Chromium's configuration (third_party/libxslt/chromium/roll.py)
cd "$PROJECT/libxslt"
./autogen.sh \
    --with-libxml-src=../libxml2 \
    --disable-shared \
    --without-python \
    --without-crypto \
    --without-debug \
    --without-debugger \
    --without-mem-debug \
    --without-plugins \
    $CONFIGUREFLAGS
make -j$(nproc)

# upstream fuzz targets (same as oss-fuzz/projects/libxslt/build.sh)
cd tests/fuzz
make fuzz.o
for F in xpath xslt; do
    make $F.o
    $CC $CFLAGS \
        $F.o fuzz.o \
        -o /out/libxslt-$F.wasm \
        $LIB_FUZZING_ENGINE \
        ../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
        ../../../libxml2/.libs/libxml2.a -lm
done
