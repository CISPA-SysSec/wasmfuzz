set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" aba9161b72c028aa8a1ce15aabd92e3c3cdb2da3
git -C "$PROJECT/repo" apply "$PROJECT/huh.patch"
