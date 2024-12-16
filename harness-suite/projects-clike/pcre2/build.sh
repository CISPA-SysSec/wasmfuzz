#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

./autogen.sh
./configure --host=wasm32-wasi \
    --enable-fuzz-support --enable-never-backslash-C \
    --disable-pcre2grep-callout --disable-jit \
    --with-match-limit=1000 --with-match-limit-depth=1000

make libpcre2-8.la .libs/libpcre2-fuzzsupport.a -j"$(nproc)"

# build fuzzer
$CC $CFLAGS $FUZZ_LDFLAGS -o pcre2fuzzcheck \
    .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a

cp pcre2fuzzcheck /out/pcre2-fuzzcheck.wasm
