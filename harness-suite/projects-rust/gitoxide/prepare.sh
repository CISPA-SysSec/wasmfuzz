set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 298f22ee0086df86e1cae45bcb76cc8b9cad9102
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-fs-wasi.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-index-wasi.patch"
