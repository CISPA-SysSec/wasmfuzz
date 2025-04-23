set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" edb449c9dd60f74562dc78a33e41cfcb5d7be81e
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-fs-wasi.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-index-wasi.patch"
