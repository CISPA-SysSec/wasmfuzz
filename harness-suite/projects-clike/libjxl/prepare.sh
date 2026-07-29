set -e

git clone-rev.sh https://github.com/libjxl/libjxl "$PROJECT/repo" 196a43d996aa6ed33ebf98812a7c6d43b2b6d01b --recursive
git -C "$PROJECT/repo" apply ../fix-wasi-threads.patch
