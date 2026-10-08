#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Mirror Firefox's other-licenses/snappy/moz.build: no cmake, config via -D.
# sys/mman.h is omitted (needs wasi emulated mman; only used by test code).
# No SSSE3/BMI2/NEON/CRC32 paths on wasm32.
sed -e 's/${HAVE_SYS_UIO_H_01}/1/g' \
    -e 's/${PROJECT_VERSION_MAJOR}/1/' \
    -e 's/${PROJECT_VERSION_MINOR}/3/' \
    -e 's/${PROJECT_VERSION_PATCH}/0/' \
    snappy-stubs-public.h.in > snappy-stubs-public.h

SNAPPY_DEFS="-DHAVE_ATTRIBUTE_ALWAYS_INLINE=1 -DHAVE_BUILTIN_CTZ=1 \
  -DHAVE_BUILTIN_EXPECT=1 -DHAVE_BUILTIN_PREFETCH=1 -DHAVE_SYS_RESOURCE_H=1 \
  -DHAVE_SYS_TIME_H=1 -DHAVE_SYS_UIO_H=1 -DHAVE_UNISTD_H=1 \
  -DSNAPPY_HAVE_SSSE3=0 -DSNAPPY_HAVE_X86_CRC32=0 -DSNAPPY_HAVE_BMI2=0 \
  -DSNAPPY_HAVE_NEON=0 -DSNAPPY_HAVE_NEON_CRC32=0 -DSNAPPY_IS_BIG_ENDIAN=0"

OBJS=""
for src in snappy.cc snappy-c.cc snappy-sinksource.cc snappy-stubs-internal.cc; do
  $CXX $CXXFLAGS -std=c++17 $SNAPPY_DEFS -Wno-sign-compare -Wno-unused-function \
      -I. -c $src -o ${src%.cc}.o
  OBJS="$OBJS ${src%.cc}.o"
done

for fuzzer in snappy_uncompress_fuzzer snappy_compress_fuzzer; do
  $CXX $CXXFLAGS -std=c++17 $SNAPPY_DEFS -I. $fuzzer.cc $OBJS \
      $LIB_FUZZING_ENGINE -o /out/snappy-${fuzzer#snappy_}.wasm
done
