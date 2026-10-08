set -e
# png at upstream HEAD; Chromium ships 0.18.1 (third_party/rust/png/v0_18/README.chromium).
git clone-rev.sh https://github.com/image-rs/image-png.git "$PROJECT/repo" b2f10c6a7e3127d4aaf231f3eae731a33e6eb0bc
# Adds `chromium_skia` (mirrors Skia's SkPngRustCodec usage incl. streaming/APNG/transformations)
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-chromium-skia-harness.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-buf-independent-retry-finish.patch"
