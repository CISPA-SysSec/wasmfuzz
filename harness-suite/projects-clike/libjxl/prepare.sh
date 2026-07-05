set -e

git clone-rev.sh https://github.com/libjxl/libjxl "$PROJECT/repo" a7a9c787341cf703dede03c2009fa460cae5e5df --recursive
git -C "$PROJECT/repo" apply ../fix-wasi-threads.patch
