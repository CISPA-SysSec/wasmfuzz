set -e

git clone-rev.sh https://github.com/harfbuzz/harfbuzz "$PROJECT/repo" a8dc5479c55c7e51c0e8d576ae379b5dbb4e8f67
git -C "$PROJECT/repo" apply ../port-wasi-mman.patch
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-meson-subset-fuzzers.patch
