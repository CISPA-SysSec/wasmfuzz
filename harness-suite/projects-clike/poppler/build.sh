#!/bin/bash
set -e +x
source set-buildflags.sh

# poppler uses setjmp/longjmp via freetype and signal.h in some sources.
export CFLAGS="$CFLAGS -D_WASI_EMULATED_SIGNAL"
export CXXFLAGS="$CXXFLAGS -D_WASI_EMULATED_SIGNAL"

DEPS_PATH="$PROJECT/deps"
mkdir -p "$DEPS_PATH"

cd "$PROJECT/zlib"
./configure $CONFIGUREFLAGS
make -j"$(nproc)" install \
    prefix=/wasi-sdk/share/wasi-sysroot/ \
    libdir=/wasi-sdk/share/wasi-sysroot/lib/wasm32-wasip1/

echo "=== Building freetype ==="
cd "$PROJECT/freetype"
./autogen.sh
./configure $CONFIGUREFLAGS --enable-static --disable-shared \
    --with-harfbuzz=no --with-brotli=no --with-png=no --with-bzip2=no \
    --prefix="$DEPS_PATH"
make -j"$(nproc)" install

echo "=== Building wasi iconv stub ==="
mkdir -p "$DEPS_PATH/include" "$DEPS_PATH/lib"
cp "$PROJECT/wasi-iconv.h" "$DEPS_PATH/include/iconv.h"
$CC $CFLAGS -c "$PROJECT/wasi-iconv.c" -I"$PROJECT" -o "$DEPS_PATH/lib/wasi-iconv.o"
rm -f "$DEPS_PATH/lib/libiconv.a"
ar rcs "$DEPS_PATH/lib/libiconv.a" "$DEPS_PATH/lib/wasi-iconv.o"

echo "=== Building poppler ==="
mkdir -p "$PROJECT/repo/build"
cd "$PROJECT/repo/build"
export PKG_CONFIG_PATH="$DEPS_PATH/lib/pkgconfig"
# poppler-cpp uses exceptions; drop the harness-wide -fno-exceptions flag.
saved_cxxflags="$CXXFLAGS"
export CXXFLAGS="${CXXFLAGS//-fno-exceptions/}"
WASI_SYSROOT="$WASI_SDK_PREFIX/share/wasi-sysroot"
PKG_CONFIG="pkg-config --static" cmake -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}" \
    -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
    -DZLIB_LIBRARY="$WASI_SYSROOT/lib/wasm32-wasip1/libz.a" \
    -DZLIB_INCLUDE_DIR="$WASI_SYSROOT/include" \
    -DIconv_INCLUDE_DIR="$DEPS_PATH/include" \
    -DIconv_LIBRARY="$DEPS_PATH/lib/libiconv.a" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_FUZZER=OFF \
    -DFONT_CONFIGURATION=generic \
    -DENABLE_LIBJPEG=OFF \
    -DENABLE_LIBOPENJPEG=OFF \
    -DENABLE_LCMS=OFF \
    -DENABLE_GOBJECT_INTROSPECTION=OFF \
    -DENABLE_LIBPNG=OFF \
    -DENABLE_ZLIB=OFF \
    -DENABLE_LIBTIFF=OFF \
    -DENABLE_GLIB=OFF \
    -DENABLE_LIBCURL=OFF \
    -DENABLE_GPGME=OFF \
    -DENABLE_NSS3=OFF \
    -DENABLE_QT6=OFF \
    -DENABLE_QT5=OFF \
    -DENABLE_UTILS=OFF \
    -DENABLE_BOOST=OFF \
    -DENABLE_ZLIB_UNCOMPRESS=ON \
    -DBUILD_GTK_TESTS=OFF \
    -DBUILD_QT5_TESTS=OFF \
    -DBUILD_QT6_TESTS=OFF \
    -DBUILD_CPP_TESTS=OFF \
    -DBUILD_MANUAL_TESTS=OFF \
    -DCMAKE_CXX_SCAN_FOR_MODULES=OFF \
    ..
ninja poppler poppler-cpp

POPPLER_INCLUDES=(
    -I"$PROJECT/repo/cpp"
    -I"$PROJECT/repo/build/cpp"
)
POPPLER_LIBS=(
    "$PROJECT/repo/build/cpp/libpoppler-cpp.a"
    "$PROJECT/repo/build/libpoppler.a"
    -L"$DEPS_PATH/lib" -lfreetype
    -lz
    -lm
    -lwasi-emulated-signal
)
ICONV_LIB="$DEPS_PATH/lib/libiconv.a"

poppler_fuzzers=(
    doc
    pdf
    page_label
    page_search
    # pdf_file: pdf_file is pdf but with a temp file on disk
)

for fuzzer in "${poppler_fuzzers[@]}"; do
    $CXX $CXXFLAGS -std=c++20 "${POPPLER_INCLUDES[@]}" \
        "$PROJECT/repo/cpp/tests/fuzzing/${fuzzer}_fuzzer.cc" \
        "${POPPLER_LIBS[@]}" \
        $LIB_FUZZING_ENGINE \
        "$ICONV_LIB" \
        -o "/out/poppler-${fuzzer}.wasm"
done

export CXXFLAGS="$saved_cxxflags"
