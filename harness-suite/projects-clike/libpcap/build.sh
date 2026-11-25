#!/bin/bash
set -e +x
source set-buildflags.sh

# wasi-include: <netdb.h> shim (lookup stubs in wasi-netdb.c; WASI has no name
# service) and a <setjmp.h> that maps longjmp to exit_testcase.
export CFLAGS="$CFLAGS -I$PROJECT/wasi-include -D_WASI_EMULATED_SIGNAL"

cd "$PROJECT/repo"
mkdir -p build && cd build
# offline-only libpcap: no capture devices on WASI
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN_FILE" \
    -DWASI_SDK_PREFIX="$WASI_SDK_PREFIX" \
    -DCMAKE_BUILD_TYPE=None \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF \
    -DPCAP_TYPE=null \
    -DDISABLE_DBUS=ON -DDISABLE_RDMA=ON -DDISABLE_DPDK=ON -DDISABLE_BLUETOOTH=ON \
    -DDISABLE_NETMAP=ON -DDISABLE_LINUX_USBMON=ON -DENABLE_REMOTE=OFF \
    -DBUILD_WITH_LIBNL=OFF \
    -DSTDLIBS_HAVE_GETADDRINFO=1
make -j"$(nproc)" pcap_static

$CC $CFLAGS -I.. -I. -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o
$CC $CFLAGS -c "$PROJECT/wasi-netdb.c" -o wasi-netdb.o
$CXX $CXXFLAGS fuzz_both.o libpcap.a wasi-netdb.o -lwasi-emulated-signal $LIB_FUZZING_ENGINE -o /out/libpcap-fuzz_both.wasm
