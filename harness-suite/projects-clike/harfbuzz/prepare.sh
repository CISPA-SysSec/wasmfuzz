set -e

git clone-rev.sh https://github.com/harfbuzz/harfbuzz "$PROJECT/repo" cce964cb4f3f29a9addbb079b52c7a712fba93b8
git -C "$PROJECT/repo" apply ../fix-wasi-mman.patch
git -C "$PROJECT/repo" apply ../fix-wasi-threads.patch
