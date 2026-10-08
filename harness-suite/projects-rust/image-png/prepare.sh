set -e
# png at upstream HEAD; Chromium ships 0.18.1 (third_party/rust/png/v0_18/README.chromium).
git clone-rev.sh https://github.com/image-rs/image-png.git "$PROJECT/repo" b2f10c6a7e3127d4aaf231f3eae731a33e6eb0bc
# Adds `chromium_skia` (mirrors Skia's SkPngRustCodec usage incl. streaming/APNG/transformations)
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-chromium-skia-harness.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-buf-independent-retry-finish.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-interlaced-frame-size-empty-passes.patch"

# fdeflate as resolved by png 0.18.1 for the fuzz workspace (latest 0.3.x), vendored for its fix.
curl -fsSL -o "$PROJECT/fdeflate.crate" https://static.crates.io/crates/fdeflate/0.3.7/download
mkdir -p "$PROJECT/fdeflate"
tar -xzf "$PROJECT/fdeflate.crate" -C "$PROJECT/fdeflate" --strip-components=1
patch -d "$PROJECT/fdeflate" -p1 <"$PROJECT/fix-fdeflate-defer-error-after-output.patch"
rm -f "$PROJECT/fdeflate.crate"
git -C "$PROJECT/repo" apply "$PROJECT/port-vendored-fdeflate.patch"
