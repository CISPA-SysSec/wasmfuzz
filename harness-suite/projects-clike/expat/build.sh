#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"


export CFLAGS="$CCFLAGS"
export CXXFLAGS="$CCFLAGS -fno-exceptions"

# not sure what's going on here, but the build is broken without this:
export CFLAGS="$CFLAGS -D_GNU_SOURCE=1"
export CXXFLAGS="$CXXFLAGS -D_GNU_SOURCE=1"

cmake_args=(
  -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}"
  # Specific to Expat
  -DEXPAT_SHARED_LIBS=OFF
  -DEXPAT_OSSFUZZ_BUILD=ON
  -DEXPAT_BUILD_FUZZERS=ON
  -DEXPAT_BUILD_EXAMPLES=OFF
  -DEXPAT_BUILD_TESTS=OFF
  -DEXPAT_BUILD_TOOLS=OFF

  -DCMAKE_C_FLAGS="${CFLAGS}"
  -DCMAKE_CXX_FLAGS="${CXXFLAGS}"
)

mkdir -p build
cd build
cmake ../expat "${cmake_args[@]}"
make -j$(nproc)

for fuzzer in fuzz/*;
do
  fuzzer_name=$(basename $fuzzer)
  if [[ $fuzzer_name == *"UTF-16"* ]]; then
    continue
  fi
  if [[ $fuzzer_name == *"ISO-8859"* ]]; then
    continue
  fi
  cp $fuzzer /out/expat-$fuzzer_name.wasm
done
