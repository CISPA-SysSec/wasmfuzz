set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" f3982866bec6390d3508c12dc0752813189e6a81
git -C "$PROJECT/repo" apply "$PROJECT/huh.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-panics.patch"
rm "$PROJECT/repo/rust-toolchain.toml"