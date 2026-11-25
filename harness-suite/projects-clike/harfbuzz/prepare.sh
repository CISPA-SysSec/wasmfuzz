set -e

git clone-rev.sh https://github.com/harfbuzz/harfbuzz "$PROJECT/repo" cad7de9931e4bd36f2a148f61fa8b322d968ad1e
git -C "$PROJECT/repo" apply ../port-wasi-mman.patch
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
