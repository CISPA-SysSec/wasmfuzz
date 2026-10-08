#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo/tests/fuzz"
LIB=../../lib

# Mirrors oss-fuzz's `fuzz.py build` (DEBUGLEVEL=1) but for wasm32-wasip1:
# - no ZSTD_MULTITHREAD / -pthread
# - ZSTD_DISABLE_ASM (no huf_decompress_amd64.S; generic C paths)
# - ZSTD_LEGACY_SUPPORT=0: neither Chromium nor Firefox build lib/legacy
ZSTD_CPPFLAGS="-I$LIB -I$LIB/common -I$LIB/compress -I$LIB/dictBuilder \
  -I$LIB/decompress -I$LIB/deprecated -I../../contrib/externalSequenceProducer \
  -DDEBUGLEVEL=1 -DMEM_FORCE_MEMORY_ACCESS=0 -DZSTD_DISABLE_ASM=1 \
  -DZSTD_LEGACY_SUPPORT=0 -DXXH_NAMESPACE=ZSTD_"

LIB_SRCS="$(ls $LIB/common/*.c $LIB/compress/*.c $LIB/decompress/*.c $LIB/dictBuilder/*.c) \
  ./fuzz_helpers.c ./zstd_helpers.c ./fuzz_data_producer.c \
  ../../contrib/externalSequenceProducer/sequence_producer.c"

build_objs() {
  local dir=$1; shift
  mkdir -p $dir
  for src in $LIB_SRCS; do
    $CC $CFLAGS $ZSTD_CPPFLAGS "$@" -c $src -o $dir/$(echo $src | tr '/.' '__').o &
  done
  wait
}
# decompression-style targets and round-trip targets use different flags upstream
build_objs objs-d
build_objs objs-rt -DFUZZING_ASSERT_VALID_SEQUENCE

DECOMP_TARGETS="simple_decompress stream_decompress block_decompress \
  dictionary_decompress zstd_frame_info decompress_dstSize_tooSmall \
  huf_decompress fse_read_ncount dictionary_loader"
RT_TARGETS="simple_round_trip stream_round_trip block_round_trip \
  dictionary_round_trip dictionary_stream_round_trip raw_dictionary_round_trip \
  simple_compress huf_round_trip sequence_compression_api"

for t in $DECOMP_TARGETS; do
  $CC $CFLAGS $ZSTD_CPPFLAGS $t.c objs-d/*.o $LIB_FUZZING_ENGINE -o /out/zstd-$t.wasm
done
for t in $RT_TARGETS; do
  $CC $CFLAGS $ZSTD_CPPFLAGS -DFUZZING_ASSERT_VALID_SEQUENCE $t.c objs-rt/*.o \
      $LIB_FUZZING_ENGINE -o /out/zstd-$t.wasm
done
