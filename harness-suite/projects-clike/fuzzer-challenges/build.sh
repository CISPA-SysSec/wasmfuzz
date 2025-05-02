#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

export CFLAGS="$CFLAGS $FUZZ_LDFLAGS"
export CXXFLAGS="$CXXFLAGS $FUZZ_LDFLAGS"

make compile
# Note: test-u128 is hard to solve in WASM due to the u128 lowering.
#       test-transform is just hard to solve in general.
for target in test-*.c; do
    target="${target%.c}"
    cp "$target" "/out/fuzzer-challenges-${target#test-}.wasm"
done

cd libfuzzer
make compile
rm KeepSeedTest* # Requires repeated TestOneInput calls
rm TableLookupTest* # __libfuzzer_extra_counters
# TODO: why is SimpleCmp not solved?

for target in *Test.cpp; do
    target="${target%.cpp}"
    cp "$target" "/out/fuzzer-challenges-${target%Test}.wasm"
done
