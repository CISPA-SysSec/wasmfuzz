set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 21fecdf928336ac5fa3dd1402f92e8200d8aff62
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-fs-wasi.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-index-wasi.patch"
