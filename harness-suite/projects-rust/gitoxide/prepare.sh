set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 4278d183285bb0b2f8f3cc74d1432d3e77c4dc38
git -C "$PROJECT/repo" apply "$PROJECT/disable-incompatible.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-wasi-path-and-ewah.patch"
