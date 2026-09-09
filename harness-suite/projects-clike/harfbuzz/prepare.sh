set -e

git clone-rev.sh https://github.com/harfbuzz/harfbuzz "$PROJECT/repo" bc678801ce4be8e83c5b7c013fca805ea71a38e4
git -C "$PROJECT/repo" apply ../fix-wasi-mman.patch
git -C "$PROJECT/repo" apply ../fix-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-meson-subset-fuzzers.patch
