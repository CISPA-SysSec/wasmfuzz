set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 45ec08d150f81894d945b5163bf84fd7e284ef41
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-wasi-path-and-ewah.patch"
