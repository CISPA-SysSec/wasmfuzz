set -e
git clone-rev.sh https://github.com/zip-rs/zip2.git "$PROJECT/repo" 6d3945645b7f3805068dd8c50d4fe56a66651069
git -C "$PROJECT/repo" apply "$PROJECT/no-jemalloc.patch"
