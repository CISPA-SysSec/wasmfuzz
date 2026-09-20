set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 77c8cd956c08a2757318d3a0e6ef30d7fa71286e
git -C "$PROJECT/repo" apply "$PROJECT/port-disable-incompatible-fuzz.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-ewah-chunk-len-overflow.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasi-path-convert.patch"
