set -e
# Independent Lean 4 kernel in Rust (single-threaded, wasm32-wasip1 upstream); the lean-kernel-arena's pinned rev, no fuzz targets upstream.
git clone-rev.sh https://github.com/dmitrykorolev/kefir "$PROJECT/repo" 4f69ffb45e16033944926a3fe20e5f3a231b580a
git -C "$PROJECT/repo" apply "$PROJECT/port-wasm32-fuzzing-layout.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-fuzzing-budgets.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-ndjson-harness.patch"
# Resolve the fuzz workspace from upstream's lockfile (exact pins).
cp "$PROJECT/repo/Cargo.lock" "$PROJECT/repo/fuzz/Cargo.lock"
