set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" 72bb53b0ed9c49b49f71d738cfe3acc982ce7ab0
git -C "$PROJECT/repo" apply "$PROJECT/huh.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-panics.patch"
rm "$PROJECT/repo/rust-toolchain.toml"