#!/bin/bash
set -e +x
source set-buildflags.sh

# --- BoringSSL (libcrypto only), as used by Chromium's libsrtp -------------
# No asm, no threads (wasm32-wasip1), no sockets.
BSSL_FLAGS="-DOPENSSL_NO_ASM -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED -DOPENSSL_NO_SOCK"
cmake -S "$PROJECT/boringssl" -B "$PROJECT/boringssl/build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN_FILE" -DWASI_SDK_PREFIX="$WASI_SDK_PREFIX" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DOPENSSL_NO_ASM=1 \
    -DCMAKE_C_FLAGS="$CFLAGS $BSSL_FLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS $BSSL_FLAGS"
ninja -C "$PROJECT/boringssl/build" crypto
BSSL_INC="$PROJECT/boringssl/include"
BSSL_LIB="$PROJECT/boringssl/build/libcrypto.a"

# --- libsrtp (upstream HEAD, 3.x) with the OpenSSL backend on BoringSSL; the
# source list matches CMakeLists.txt for CRYPTO_LIBRARY=openssl. The -D set
# replaces the CMake-generated config.h (an empty one satisfies HAVE_CONFIG_H).
cd "$PROJECT/libsrtp"
SRTP_DEFS=(
  -DPACKAGE_STRING='"libsrtp3 3.0.0"'
  -DPACKAGE_VERSION='"3.0.0"'
  -DHAVE_CONFIG_H -DOPENSSL -DGCM
  -DHAVE_STDLIB_H -DHAVE_STDINT_H -DHAVE_INTTYPES_H
  -DHAVE_INT32_T -DHAVE_UINT8_T -DHAVE_UINT16_T -DHAVE_UINT32_T -DHAVE_UINT64_T
  -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H -DHAVE_SYS_TYPES_H -DHAVE_UNISTD_H -DHAVE_INLINE
)
SRTP_INC=(-Ibuild/config -Iinclude -Icrypto/include -I"$BSSL_INC")
SRTP_SRCS=(
  crypto/cipher/aes_gcm_ossl.c crypto/cipher/aes_icm_ossl.c crypto/cipher/cipher.c
  crypto/cipher/cipher_test_cases.c crypto/cipher/null_cipher.c
  crypto/hash/auth.c crypto/hash/auth_test_cases.c crypto/hash/hmac_ossl.c crypto/hash/null_auth.c
  crypto/kernel/alloc.c crypto/kernel/crypto_kernel.c crypto/kernel/err.c crypto/kernel/key.c
  crypto/math/datatypes.c crypto/replay/rdb.c crypto/replay/rdbx.c srtp/srtp.c srtp/srtp_policy.c
)
mkdir -p build/config
: > build/config/config.h
for src in "${SRTP_SRCS[@]}"; do
  $CC $CFLAGS "${SRTP_DEFS[@]}" "${SRTP_INC[@]}" -c "$src" -o "build/$(echo "$src" | tr / _).o"
done
llvm-ar rcs build/libsrtp.a build/*.o

# --- Chromium's libsrtp_fuzzer (testing/libfuzzer/fuzzers), //base-free port
# adapted to the 3.x policy API (see the header of libsrtp_fuzzer.cc)
$CXX $CXXFLAGS -std=c++17 "${SRTP_DEFS[@]}" "${SRTP_INC[@]}" -Itest \
    "$PROJECT/libsrtp_fuzzer.cc" build/libsrtp.a "$BSSL_LIB" \
    $LIB_FUZZING_ENGINE -o /out/libsrtp-chromium_fuzzer.wasm

# --- upstream srtp-fuzzer (fuzzer/, as used by oss-fuzz) from the same tree
FZ="$PROJECT/libsrtp/fuzzer"
$CC $CFLAGS "${SRTP_DEFS[@]}" "${SRTP_INC[@]}" -c "$FZ/fuzzer.c" -o build/fuzzer.o
$CC $CFLAGS -O0 -c "$FZ/testmem.c" -o build/testmem.o
$CXX $CXXFLAGS -std=c++11 -c "$FZ/mt19937.cpp" -o build/mt19937.o
$CXX $CXXFLAGS build/fuzzer.o build/testmem.o build/mt19937.o build/libsrtp.a "$BSSL_LIB" \
    $LIB_FUZZING_ENGINE -o /out/libsrtp-srtp-fuzzer.wasm
