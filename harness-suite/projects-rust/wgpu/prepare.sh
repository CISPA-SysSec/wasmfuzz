set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" 8b419de0906f37af69d728f1735132e427a3436f
git -C "$PROJECT/repo" apply "$PROJECT/huh.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-naga-panics.patch"
rm "$PROJECT/repo/rust-toolchain.toml"