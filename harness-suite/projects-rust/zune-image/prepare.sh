set -e
git clone-rev.sh https://github.com/etemesi254/zune-image "$PROJECT/repo" f873e3f01e2cfa3f23bc698290f2d68dda5f846d
git -C "$PROJECT/repo" apply "$PROJECT/wasm.patch"

