export WASI_SDK_PREFIX=/wasi-sdk/

export CC="$WASI_SDK_PREFIX/bin/clang"
export CXX="$WASI_SDK_PREFIX/bin/clang++"
export LD="$WASI_SDK_PREFIX/bin/wasm-ld"
export PATH="$WASI_SDK_PREFIX/bin/:$PATH"

TARGET_FLAGS="--sysroot=$WASI_SDK_PREFIX/share/wasi-sysroot --target=wasm32-wasi"


# export CCFLAGS="-g -gdwarf-5 -gembed-source -O0 -flto -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CCFLAGS="-g -gdwarf-5 -gembed-source -O2 -flto=thin -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

export CFLAGS="$CFLAGS $TARGET_FLAGS $CCFLAGS"
export CXXFLAGS="$CXXFLAGS $TARGET_FLAGS $CCFLAGS -fno-exceptions"
export CONFIGUREFLAGS="--host=wasm32-wasi"

# default stack size: 1MB
# we use 8MB instead to work around a pcre2 crash
export FUZZ_LDFLAGS="-Wl,--export=malloc,--export=LLVMFuzzerTestOneInput,\
--export=LLVMFuzzerInitialize,--warn-unresolved-symbols,-zstack-size=8388608 \
    -mexec-model=reactor"
export LIB_FUZZING_ENGINE="$FUZZ_LDFLAGS"

# TODO: can we pass WASI_SDK_PREFIX to cmake automatically?
export CMAKE_TOOLCHAIN_FILE=$WASI_SDK_PREFIX/share/cmake/wasi-sdk.cmake

. "$HOME/.cargo/env"

export SOURCE_DATE_EPOCH=1456304492
