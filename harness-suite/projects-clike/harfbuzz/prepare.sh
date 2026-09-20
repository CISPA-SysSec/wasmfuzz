set -e

git clone-rev.sh https://github.com/harfbuzz/harfbuzz "$PROJECT/repo" 240a7d7b8bb74409c1707ae88ba4a71a9b774d0c
git -C "$PROJECT/repo" apply ../port-wasi-mman.patch
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-meson-subset-fuzzers.patch
