set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 36a846f23ae0a3dfe95648605f0f618ccb55a881
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-fs-wasi.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-index-wasi.patch"
