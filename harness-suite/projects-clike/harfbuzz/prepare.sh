set -e

git clone-rev.sh https://github.com/harfbuzz/harfbuzz "$PROJECT/repo" 511df88b82e697cd2a0f1f0635787aa0b18bddbb
git -C "$PROJECT/repo" apply ../fix-wasi-mman.patch
git -C "$PROJECT/repo" apply ../fix-wasi-threads.patch
