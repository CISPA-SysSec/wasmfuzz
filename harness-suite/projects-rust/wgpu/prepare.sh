set -e
git clone-rev.sh https://github.com/gfx-rs/wgpu.git "$PROJECT/repo" d8833d079833c62b4fd00325d0ba08ec0c8bc309
git -C "$PROJECT/repo" apply "$PROJECT/huh.patch"
