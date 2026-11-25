set -e
# Lean 4 kernel in Rust, closure-based conversion (a distant nanoda fork); the lean-kernel-arena's pinned rev, no fuzz targets upstream.
git clone-rev.sh https://github.com/intgrah/sokonanoda "$PROJECT/repo" 15f5eaa32064c2d1ac2aa7683091fef712d42f7b
git -C "$PROJECT/repo" apply "$PROJECT/port-wasm32.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasm32-recursion-limit.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-reject-loose-bvars.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-parser-malformed-records.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-fuzzing-index-bound.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-ndjson-harness.patch"
# Resolve the fuzz workspace from upstream's lockfile.
cp "$PROJECT/repo/Cargo.lock" "$PROJECT/repo/fuzz/Cargo.lock"
