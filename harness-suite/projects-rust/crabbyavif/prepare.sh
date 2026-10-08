set -e
# CrabbyAvif at upstream HEAD; Chromium ships e7d2dcf799 (third_party/crabbyavif/README.chromium).
git clone-rev.sh https://github.com/webmproject/CrabbyAvif.git "$PROJECT/repo" 9723084c3a767ffc28a91e375b864a17f4682b5d
# AV1 backend: dav1d at upstream HEAD (as used by Chromium through CrabbyAvif).
git clone-rev.sh https://github.com/videolan/dav1d "$PROJECT/repo/sys/dav1d-sys/dav1d" bf5a8792744ee78c977dfb16503f9156dde6401d
git -C "$PROJECT/repo/sys/dav1d-sys/dav1d" apply "$PROJECT/port-dav1d-wasi-meson.patch"
# libyuv at upstream HEAD.
git clone-rev.sh https://chromium.googlesource.com/libyuv/libyuv "$PROJECT/repo/sys/libyuv-sys/libyuv" 2124173f34062726761163018f79df085d911460
# CrabbyAvif has no cargo-fuzz dir upstream; add one mirroring Chromium's usage.
mkdir -p "$PROJECT/repo/fuzz"
cp -r "$PROJECT/fuzz-template/fuzz_targets" "$PROJECT/repo/fuzz/"
cp "$PROJECT/fuzz-template/Cargo.toml.in" "$PROJECT/repo/fuzz/Cargo.toml"
cp "$PROJECT/fuzz-template/build.rs" "$PROJECT/repo/fuzz/build.rs"
git -C "$PROJECT/repo" apply "$PROJECT/fix-mini-alpha-item-data-size-zero.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-sato-without-input-items.patch"
