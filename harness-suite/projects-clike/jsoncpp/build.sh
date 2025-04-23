#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

export CCFLAGS="$CCFLAGS -DJSON_USE_EXCEPTION=0"
export CFLAGS="$CCFLAGS"
export CXXFLAGS="$CCFLAGS -fno-exceptions"

cmake_args=(
  -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}"

  -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF
  -DJSONCPP_WITH_TESTS=OFF
  -DBUILD_SHARED_LIBS=OFF
  -G"Unix Makefiles"

  -DCMAKE_C_FLAGS="${CFLAGS}"
  -DCMAKE_CXX_FLAGS="${CXXFLAGS}"
)

mkdir -p build
cd build
cmake ../ "${cmake_args[@]}"
make -j$(nproc)

$CXX $CXXFLAGS -I../include $LIB_FUZZING_ENGINE \
    ../src/test_lib_json/fuzz.cpp -o /out/jsoncpp-fuzzer.wasm \
    lib/libjsoncpp.a
