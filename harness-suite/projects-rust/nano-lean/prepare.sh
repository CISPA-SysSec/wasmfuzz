set -e
# Lean 4 kernel checker; upstream HEAD, no fuzz targets upstream.
git clone-rev.sh https://github.com/sdiehl/nano-lean "$PROJECT/repo" e5915446d9438e96da7b2ce19575a06223a8ef62
git -C "$PROJECT/repo" apply "$PROJECT/port-wasm32.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-blean-ndjson-harnesses.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-stack-guards.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasm-stack-budget.patch"
# Resolve the fuzz workspace from upstream's lockfile.
cp "$PROJECT/repo/Cargo.lock" "$PROJECT/repo/fuzz/Cargo.lock"

# olean-export as locked by nano-lean, vendored for its port patch.
curl -fsSL -o "$PROJECT/olean-export.crate" https://static.crates.io/crates/olean-export/0.6.0/download
echo "0c6d8d3641fcef0043c740b8afebfaf96737a73d6b49e7c931f034b3bcbed26b  $PROJECT/olean-export.crate" | sha256sum -c -
mkdir -p "$PROJECT/olean-export"
tar -xzf "$PROJECT/olean-export.crate" -C "$PROJECT/olean-export" --strip-components=1
patch -d "$PROJECT/olean-export" -p1 <"$PROJECT/port-olean-export-advise-unix.patch"
rm -f "$PROJECT/olean-export.crate"
git -C "$PROJECT/repo" apply "$PROJECT/port-vendored-olean-export.patch"
