set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" f38e1c91eacd6a95c58401240f938421a023753a
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-fs-wasi.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-index-wasi.patch"
