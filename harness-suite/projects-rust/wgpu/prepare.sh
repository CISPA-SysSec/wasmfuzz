set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" 1edb79d1bdc17ef3cf042d9e0e72f7c46c5ce48e
git -C "$PROJECT/repo" apply "$PROJECT/port-naga-fuzz-wasm.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-panics.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-glsl-layout-too-large.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-spv-empty-index.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-const-eval-panics.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-glsl-const-context-panics.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-naga-zero-value-elements.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-spv-malformed-module-panics.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-naga-spv-composite-insert-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-glsl-entry-point-arrays.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-naga-nesting-depth.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-spv-fake-function-ids.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-spv-ballot-find-emitter.patch"

# Pinned to the version in the wgpu Cargo.lock.
curl -fsSL -o "$PROJECT/pp-rs.crate" https://static.crates.io/crates/pp-rs/0.2.1/download
mkdir -p "$PROJECT/pp-rs"
tar -xzf "$PROJECT/pp-rs.crate" -C "$PROJECT/pp-rs" --strip-components=1
patch -d "$PROJECT/pp-rs" -p1 <"$PROJECT/fix-pp-rs-recursive-define-parameters.patch"
patch -d "$PROJECT/pp-rs" -p1 <"$PROJECT/fix-pp-rs-nested-if-expression.patch"
rm -f "$PROJECT/pp-rs.crate"
git -C "$PROJECT/repo" apply "$PROJECT/port-vendored-crate-patches.patch"
rm "$PROJECT/repo/rust-toolchain.toml"
