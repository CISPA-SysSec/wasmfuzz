set -e

git clone-rev.sh https://github.com/libjxl/libjxl "$PROJECT/repo" b5def9fb509d0f2421c8a5bcd7aa6f5a627363c4 --recursive
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-streaming-gaborish.patch
