set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 4278d183285bb0b2f8f3cc74d1432d3e77c4dc38
git -C "$PROJECT/repo" apply "$PROJECT/port-disable-incompatible-fuzz.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-ewah-chunk-len-overflow.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasi-path-convert.patch"
