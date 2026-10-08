set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" d8548d5991199ac9ee188adb50fcdfefbc631720
git -C "$PROJECT/repo" apply "$PROJECT/port-naga-fuzz-wasm.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-panics.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-glsl-layout-too-large.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-spv-empty-index.patch"
rm "$PROJECT/repo/rust-toolchain.toml"