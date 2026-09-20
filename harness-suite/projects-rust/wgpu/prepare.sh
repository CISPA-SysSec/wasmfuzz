set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" 2b137c1e1791f062216f1b8810726e46b6e0bbf5
git -C "$PROJECT/repo" apply "$PROJECT/port-naga-fuzz-wasm.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-panics.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-glsl-layout-too-large.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-spv-empty-index.patch"
rm "$PROJECT/repo/rust-toolchain.toml"