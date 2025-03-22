set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" d55bb2956a2391e3cd003b837bb406b4c1440bc7
git -C "$PROJECT/repo" apply "$PROJECT/huh.patch"
