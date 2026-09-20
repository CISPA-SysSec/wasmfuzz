set -e

git clone-rev.sh https://github.com/libjxl/libjxl "$PROJECT/repo" b87738951c1254cd8cccaa6d47712ba735da56d8 --recursive
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-streaming-gaborish.patch
