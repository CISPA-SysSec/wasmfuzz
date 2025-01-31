set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 503098d1f93853502083fc4bf51675784879be12
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-fs-wasi.patch"
git -C "$PROJECT/repo" apply "$PROJECT/gix-index-wasi.patch"
