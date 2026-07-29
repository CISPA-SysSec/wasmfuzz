#!/bin/bash
set -e +x
source set-buildflags.sh

export CFLAGS="$CFLAGS -D_WASI_EMULATED_SIGNAL -mllvm -wasm-enable-sjlj"
export CXXFLAGS="$CXXFLAGS -D_WASI_EMULATED_SIGNAL -mllvm -wasm-enable-sjlj"

DEPS_PATH="$PROJECT/deps"
mkdir -p "$DEPS_PATH"
FFMPEG_LDFLAGS="-L$DEPS_PATH/lib -lwasi-emulated-signal -Wl,-mllvm,-wasm-enable-sjlj"

export PKG_CONFIG_PATH="$DEPS_PATH/lib/pkgconfig"
NAME_MAPPINGS="$PROJECT/repo/name_mappings.py"

FFMPEG_BUILD_ARGS=(
    --target-os=none
    --arch=x86_32
    --enable-cross-compile
    --disable-asm
    --disable-pthreads
    --disable-w32threads
    --disable-os2threads
    --disable-runtime-cpudetect
    --disable-autodetect
    --disable-stripping
)

echo "=== Building zlib ==="
cd "$PROJECT/zlib"
./configure $CONFIGUREFLAGS --prefix="$DEPS_PATH" --enable-static --disable-shared
make -j"$(nproc)" install

echo "=== Building ogg ==="
cd "$PROJECT/ogg"
./autogen.sh
./configure $CONFIGUREFLAGS --prefix="$DEPS_PATH" --enable-static --disable-shared --disable-crc
make -j"$(nproc)" install

echo "=== Building opus ==="
cd "$PROJECT/opus"
./autogen.sh
./configure $CONFIGUREFLAGS --prefix="$DEPS_PATH" --enable-static --disable-shared \
    --disable-asm --disable-rtcd --disable-intrinsics --disable-doc \
    --disable-extra-programs --disable-stack-protector
make -j"$(nproc)" install

echo "=== Building theora ==="
cd "$PROJECT/theora"
./autogen.sh
CFLAGS="$CFLAGS -fPIC" LDFLAGS="-L$DEPS_PATH/lib" \
    CPPFLAGS="$CXXFLAGS -I$DEPS_PATH/include" \
    ./configure --with-ogg="$DEPS_PATH" --prefix="$DEPS_PATH" \
    $CONFIGUREFLAGS --enable-static --disable-shared --disable-asm \
    --disable-spec --disable-examples --disable-oggtest --disable-vorbistest \
    --disable-sdltest
make -j"$(nproc)" install

echo "=== Building vorbis ==="
cd "$PROJECT/vorbis"
sed -i 's#-mno-ieee-fp##g' configure.ac
./autogen.sh
./configure $CONFIGUREFLAGS --prefix="$DEPS_PATH" --enable-static --disable-shared \
    --disable-docs --disable-examples --disable-oggtest
make -j"$(nproc)" install

# libvpx uses setjmp/longjmp; skip until we have a WASI stub (see freetype-wasi-sjlj.patch).
# git clone-rev for libvpx is kept in prepare.sh for a future enablement pass.

echo "=== Building FFmpeg ==="
cd "$PROJECT/repo"
./configure \
    --cc="$CC" --cxx="$CXX" --ld="$CXX $CXXFLAGS -std=c++11" \
    --extra-cflags="-I$DEPS_PATH/include" \
    --extra-ldflags="$FFMPEG_LDFLAGS" \
    --prefix="$DEPS_PATH" \
    --pkg-config-flags="--static" \
    --enable-ossfuzz \
    --libfuzzer="$LIB_FUZZING_ENGINE" \
    --optflags=-O1 \
    --enable-gpl \
    --enable-libopus \
    --enable-libtheora \
    --enable-libvorbis \
    --disable-libdrm \
    --disable-muxers \
    --disable-network \
    --disable-protocols \
    --disable-demuxer=rtp,rtsp,sdp \
    --disable-devices \
    --disable-shared \
    --disable-doc \
    --disable-programs \
    --enable-demuxers \
    "${FFMPEG_BUILD_ARGS[@]}"

# Build only the combined/generic fuzzers. The per-codec decoder/encoder/BSF
# targets and the per-demuxer second pass are intentionally skipped: each is a
# separate binary (hundreds total) and dominates build time. The generic
# target_dem_fuzzer / target_io_dem_fuzzer auto-probe across *all* demuxers, so
# the per-demuxer pass added no demuxer coverage.
OTHER_TARGETS=(
    tools/target_sws_fuzzer
    tools/target_swr_fuzzer
    tools/target_dem_fuzzer
    tools/target_io_dem_fuzzer
)
OTHER_NAMES=(
    "$(python3 "$NAME_MAPPINGS" binary_name other SWS)"
    "$(python3 "$NAME_MAPPINGS" binary_name other SWR)"
    "$(python3 "$NAME_MAPPINGS" binary_name other DEM)"
    "$(python3 "$NAME_MAPPINGS" binary_name other IO_DEM)"
)

make -j"$(nproc)" "${OTHER_TARGETS[@]}"

install_fuzzer() {
    local target="$1"
    local name="$2"
    cp "$target" "/out/${name}.wasm"
}

for i in "${!OTHER_TARGETS[@]}"; do
    install_fuzzer "${OTHER_TARGETS[$i]}" "${OTHER_NAMES[$i]}"
done
