export SOURCE_DATE_EPOCH=1456304492
export WASI_SDK_PREFIX=/wasi-sdk/


case $BUILD_TYPE in
    wasi-lime1)
        TARGET_FLAGS="--sysroot=$WASI_SDK_PREFIX/share/wasi-sysroot --target=wasm32-wasi -mcpu=lime1"
        ;;
    wasi-mvp)
        TARGET_FLAGS="--sysroot=$WASI_SDK_PREFIX/share/wasi-sysroot --target=wasm32-wasi -mcpu=mvp"
        ;;
    x86_64-libfuzzer)
        TARGET_FLAGS=""
        export CC="clang"
        export CXX="clang++"
        export LD="ld.lld"
        ;;
    *)
        echo "Invalid build type: $BUILD_TYPE"
        exit 1
        ;;
esac

export CCFLAGS="-g -gdwarf-5 -gembed-source -O2 -flto=thin -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

case $BUILD_TYPE in
    x86_64-libfuzzer)
        export CFLAGS="$CFLAGS $TARGET_FLAGS $CCFLAGS"
        export CXXFLAGS="$CXXFLAGS $TARGET_FLAGS $CCFLAGS"
        export CONFIGUREFLAGS=""
        export CMAKE_TOOLCHAIN_FILE=""
        ;;
    *)
        export CC="$WASI_SDK_PREFIX/bin/clang"
        export CXX="$WASI_SDK_PREFIX/bin/clang++"
        export LD="$WASI_SDK_PREFIX/bin/wasm-ld"
        export PATH="$WASI_SDK_PREFIX/bin/:$PATH"

        export CFLAGS="$CFLAGS $TARGET_FLAGS $CCFLAGS"
        export CXXFLAGS="$CXXFLAGS $TARGET_FLAGS $CCFLAGS -fno-exceptions"
        export CONFIGUREFLAGS="--host=wasm32-wasi"
        # TODO: can we pass WASI_SDK_PREFIX to cmake automatically?
        export CMAKE_TOOLCHAIN_FILE=$WASI_SDK_PREFIX/share/cmake/wasi-sdk.cmake
        ;;
esac

# default stack size: 1MB
# we use 8MB instead to work around a pcre2 crash
export FUZZ_LDFLAGS="-Wl,--export=malloc,--export=LLVMFuzzerTestOneInput,\
--export=LLVMFuzzerInitialize,--warn-unresolved-symbols,-zstack-size=8388608 \
    -mexec-model=reactor -Wl,--build-id"
export LIB_FUZZING_ENGINE="$FUZZ_LDFLAGS"

. "$HOME/.cargo/env"
