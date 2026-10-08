#!/bin/bash
set -e +x
source set-buildflags.sh

SRC="$PROJECT/repo/icu4c/source"

##################################################################
# 1) Native host build: provides the ICU build tools needed for the cross
#    build (--with-cross-build) and builds the (unfiltered) ICU data archive
#    icudt<ver>l.dat from the CLDR/ICU data sources.
mkdir -p "$PROJECT/host"
pushd "$PROJECT/host"
# (set-buildflags.sh puts wasi-sdk first in PATH, so use the system clang
# explicitly and drop the wasm flags.)
HOSTENV="env -u CFLAGS -u CXXFLAGS -u LDFLAGS -u CC -u CXX -u LD \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
$HOSTENV CC=/usr/bin/clang CXX=/usr/bin/clang++ \
  "$SRC/configure" --disable-shared --enable-static --disable-tests \
  --disable-samples --disable-extras --with-data-packaging=archive
$HOSTENV make -j$(nproc)
popd
# ICU major version from uvernum.h (the data file is named icudt<major>l.dat).
ICUVER=$(sed -n 's/^#define U_ICU_VERSION_MAJOR_NUM \([0-9]*\).*/\1/p' "$SRC/common/unicode/uvernum.h")
ICUDATA="$PROJECT/host/data/out/icudt${ICUVER}l.dat"
test -f "$ICUDATA"

##################################################################
# 2) wasm32-wasip1 build of libicuuc + libicui18n.
#  - wasi has no tzname/timezone/tzset or mmap; the default zone falls back
#    to UTC-style detection (deterministic).
#  - decContext.h includes <signal.h> (raise() is compiled out), so only the
#    header emulation define is needed, no -lwasi-emulated-signal.
#  - wasi-sdk's wasm32-wasip1 libc++ has (single-threaded stub) std::mutex /
#    condition_variable, so umutex.cpp builds unmodified.
#  - Same defines as oss-fuzz's build.sh.
DEFINES="-DU_CHARSET_IS_UTF8=1 -DU_USING_ICU_NAMESPACE=0 -DU_ENABLE_DYLOAD=0 \
  -DU_USE_STRTOD_L=0 -DU_HAVE_MMAP=0 -DU_HAVE_TZNAME=0 -D_WASI_EMULATED_SIGNAL"
export CFLAGS="$CFLAGS $DEFINES"
export CXXFLAGS="$CXXFLAGS $DEFINES"

# configure has no platform makefile fragment for wasm32-wasi ("unknown").
cp "$SRC/config/mh-linux" "$SRC/config/mh-unknown"

mkdir -p "$PROJECT/wasm"
cd "$PROJECT/wasm"
AR=llvm-ar RANLIB=llvm-ranlib "$SRC/configure" $CONFIGUREFLAGS \
  --with-cross-build="$PROJECT/host" --disable-shared --enable-static \
  --disable-tools --disable-tests --disable-samples --disable-extras \
  --disable-icuio --disable-layoutex --disable-dyload --with-data-packaging=static
mkdir -p lib bin
make -j$(nproc) -C common
make -j$(nproc) -C i18n

##################################################################
# 3) Link the full data archive in as the icudt<ver>_dat entry point (this is
#    what the static data library / genccode would provide). Compiled without
#    LTO; the blob is referenced by ucmndata/udata only via its symbol.
cp "$ICUDATA" icudt.dat
cat > icudata.c << 'EOT'
#include "unicode/utypes.h"
const unsigned char U_ICUDATA_ENTRY_POINT[] __attribute__((aligned(16))) = {
#embed "icudt.dat"
};
EOT
$CC ${CFLAGS/-flto=thin/} -std=c23 -I"$SRC/common" -c icudata.c -o icudata.o

ICU_LIBS="lib/libicui18n.a lib/libicuuc.a icudata.o"
# some upstream fuzzers rely on <cstdlib>/<iterator> arriving transitively (glibc libc++)
FUZZ_INC="-include cstdlib -include iterator -I$SRC/common -I$SRC/i18n -I$SRC/test/fuzzer"
FUZZER_PATH="$SRC/test/fuzzer"

$CXX $CXXFLAGS -std=c++17 $FUZZ_INC -c "$FUZZER_PATH/locale_util.cpp" -o locale_util.o

# Upstream fuzzers (same set oss-fuzz builds: every *_fuzzer.cpp).
for fuzzer in "$FUZZER_PATH"/*_fuzzer.cpp; do
  name=$(basename "$fuzzer" .cpp)
  $CXX $CXXFLAGS -std=c++17 $FUZZ_INC "$fuzzer" locale_util.o $ICU_LIBS \
    $LIB_FUZZING_ENGINE -o "/out/icu-${name}.wasm"
done

# Extra browser-configured harnesses (see the files for details).
for fuzzer in idna_fuzzer spoof_fuzzer; do
  $CXX $CXXFLAGS -std=c++17 $FUZZ_INC "$PROJECT/$fuzzer.cpp" $ICU_LIBS \
    $LIB_FUZZING_ENGINE -o "/out/icu-${fuzzer}.wasm"
done
