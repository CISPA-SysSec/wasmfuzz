set -e
# Lean 4 kernel in Rust (NbE over Susz, a binary form of lean4export's ndjson); the lean-kernel-arena's pinned rev, no fuzz targets upstream.
git clone-rev.sh https://github.com/jasisz/gruszka "$PROJECT/repo" 35b364d7f02c966cc0bcbda24a1628b060f00cb1
# The arena's packer: susz 0.1.4 from crates.io, with an in-memory pack.
curl -fsSL -o "$PROJECT/susz.crate" https://static.crates.io/crates/susz/0.1.4/download
mkdir -p "$PROJECT/susz"
tar -xzf "$PROJECT/susz.crate" -C "$PROJECT/susz" --strip-components=1
patch -d "$PROJECT/susz" -p1 <"$PROJECT/port-susz-pack-bytes.patch"
rm -f "$PROJECT/susz.crate"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasm32-bounded-region.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-lib-target.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-ndjson-harness.patch"
# Resolve the fuzz workspace from upstream's lockfile (its susz 0.1.1 becomes the patched 0.1.4).
cp "$PROJECT/repo/Cargo.lock" "$PROJECT/repo/fuzz/Cargo.lock"
