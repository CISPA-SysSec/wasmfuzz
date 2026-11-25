set -e
# Lean 4 kernel in Rust written from scratch (recomputes K-likeness and iota rules); the lean-kernel-arena's pinned rev, no fuzz targets upstream.
git clone-rev.sh https://github.com/sankalpsthakur/kiota "$PROJECT/repo" 606c3c08f892243d83faadf33ae2acd8bf218f78
git -C "$PROJECT/repo" apply "$PROJECT/port-wasm32-allocator.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasm32-recursion-limit.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-parser-undefined-references.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-fuzzing-index-bound.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-ndjson-harness.patch"
# Resolve the fuzz workspace from upstream's lockfile.
cp "$PROJECT/repo/Cargo.lock" "$PROJECT/repo/fuzz/Cargo.lock"
