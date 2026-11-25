set -e
# CrabbyAvif at upstream HEAD; Chromium ships e7d2dcf799 (third_party/crabbyavif/README.chromium).
git clone-rev.sh https://github.com/webmproject/CrabbyAvif.git "$PROJECT/repo" 61f0ef88f3e18d467f9cedbd76412e3cceb36787
# AV1 backend: dav1d at upstream HEAD (as used by Chromium through CrabbyAvif).
git clone-rev.sh https://github.com/videolan/dav1d "$PROJECT/repo/sys/dav1d-sys/dav1d" 918e7a67461da56f9c7b5c20842ea1d81b613945
git -C "$PROJECT/repo/sys/dav1d-sys/dav1d" apply "$PROJECT/port-dav1d-wasi-meson.patch"
# libyuv at upstream HEAD.
git clone-rev.sh https://chromium.googlesource.com/libyuv/libyuv "$PROJECT/repo/sys/libyuv-sys/libyuv" 525a3a3c726caf41c1e407c040b698cbb45e188c
# CrabbyAvif has no cargo-fuzz dir upstream; add one mirroring Chromium's usage.
mkdir -p "$PROJECT/repo/fuzz"
cp -r "$PROJECT/fuzz-template/fuzz_targets" "$PROJECT/repo/fuzz/"
cp "$PROJECT/fuzz-template/Cargo.toml.in" "$PROJECT/repo/fuzz/Cargo.toml"
cp "$PROJECT/fuzz-template/build.rs" "$PROJECT/repo/fuzz/build.rs"
