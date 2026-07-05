set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" 47cce259cbbae0da2ec50b62925ea73215f409fa
git -C "$PROJECT/repo" apply "$PROJECT/huh.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-panics.patch"
rm "$PROJECT/repo/rust-toolchain.toml"