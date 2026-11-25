set -e
# Independent Lean 4 kernel in Rust (std only); the lean-kernel-arena's pinned rev, no fuzz targets upstream.
git clone-rev.sh https://github.com/yoonwoojeong/Palladium "$PROJECT/repo" 224d2d56e6159a734d20672790bb12f10e6b65cc
git -C "$PROJECT/repo" apply "$PROJECT/port-wasm32-stack-guard.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-ndjson-harness.patch"
# Resolve the fuzz workspace from upstream's lockfile.
cp "$PROJECT/repo/Cargo.lock" "$PROJECT/repo/fuzz/Cargo.lock"
