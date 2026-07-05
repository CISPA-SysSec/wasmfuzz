set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 1b1541ed7a457afd48385c1ee39113949a9f5263
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-wasi-path-and-ewah.patch"
