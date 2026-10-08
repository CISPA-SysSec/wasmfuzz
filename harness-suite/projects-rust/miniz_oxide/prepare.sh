set -e
# upstream HEAD (Cargo.toml version 0.9.1); Chromium ships 0.8.9 and 0.9.1 (chromium_crates_io),
# Firefox ships 0.8.9 (Cargo.lock). Fuzz targets use the latest flate2 (1.1.x, on miniz_oxide 0.9),
# redirected to the local tree via [patch.crates-io].
git clone-rev.sh https://github.com/Frommi/miniz_oxide "$PROJECT/repo" e2214d401a59e91537838cc16eba82454044044f
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-harnesses.patch"
