set -e
# Lean 4 kernel written in Aver (compiled to Rust), checking Susz, a binary form of lean4export's
# ndjson; the lean-kernel-arena's pinned rev, no fuzz targets upstream.
# License: no LICENSE file upstream (checked 2026-11-22).
git clone-rev.sh https://github.com/jasisz/pestka "$PROJECT/repo" bc6471e9a9afc968485ee9a3c42ef36c14c619b8
# The Aver compiler pinned in the repo's .aver-version, from crates.io as the arena entries install
# it, into the project dir.
test "$(cat "$PROJECT/repo/.aver-version")" = 0.37.0
"$HOME/.cargo/bin/cargo" install aver-lang --version 0.37.0 --locked --root "$PROJECT/aver" --target-dir "$PROJECT/aver-target"
find "$PROJECT/aver-target" -delete
git -C "$PROJECT/repo" apply "$PROJECT/limit-fuzzing-deep-nesting.patch"
# Generate the Rust crate (`pestka`, in .build as bin/build does) for one thread: wasm32-wasip1
# has no threads, and the harness checks on one worker.
"$PROJECT/aver/bin/aver" compile "$PROJECT/repo/main.av" --module-root "$PROJECT/repo" \
    -o "$PROJECT/repo/.build" --name pestka --single-thread >/dev/null
# The arena's packer: susz 0.1.4 from crates.io, with an in-memory pack.
curl -fsSL -o "$PROJECT/susz.crate" https://static.crates.io/crates/susz/0.1.4/download
mkdir -p "$PROJECT/susz"
tar -xzf "$PROJECT/susz.crate" -C "$PROJECT/susz" --strip-components=1
patch -d "$PROJECT/susz" -p1 <"$PROJECT/port-susz-pack-bytes.patch"
rm -f "$PROJECT/susz.crate"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-ndjson-harness.patch"
