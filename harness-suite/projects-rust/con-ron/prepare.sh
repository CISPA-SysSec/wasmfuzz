set -e
# con-leche's checker ported to Rust (Lean FRO); upstream HEAD, no fuzz targets upstream.
git clone-rev.sh https://github.com/leanprover/con-ron "$PROJECT/repo" e772d54f0590d0fbb8fbcd7e400c75831de1f443
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-ndjson-harness.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasi-pread.patch"
# Resolve the fuzz workspace from upstream's lockfile.
cp "$PROJECT/repo/Cargo.lock" "$PROJECT/repo/fuzz/Cargo.lock"
