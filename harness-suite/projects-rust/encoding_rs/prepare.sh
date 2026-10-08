set -e
# encoding_rs at upstream HEAD; Firefox vendors 0.8.40 (third_party/rust/encoding_rs).
# The checkout lives in "$PROJECT/encoding_rs" because upstream's fuzz_mem target
# pulls in the reference implementation from ../../safe_encoding_rs_mem, which in
# turn depends on ../encoding_rs/.
# Default features only: `simd-accel` stays off (Firefox enables it when MOZ_RUST_SIMD is set; it is
# SIMD-only code that wasm32 lime1 cannot use, and the scalar paths are what we fuzz here).
git clone-rev.sh https://github.com/hsivonen/encoding_rs "$PROJECT/encoding_rs" a155adc7271c9e507556d053c95b459186671d2a
git clone-rev.sh https://github.com/hsivonen/safe_encoding_rs_mem "$PROJECT/safe_encoding_rs_mem" c5fd2ec0936462478b77e1ea668d95c00d7f4210
git -C "$PROJECT/encoding_rs" apply "$PROJECT/fuzz-roundtrip-harness.patch"
git -C "$PROJECT/encoding_rs" apply "$PROJECT/fix-iso2022jp-eof-replacement-space.patch"
