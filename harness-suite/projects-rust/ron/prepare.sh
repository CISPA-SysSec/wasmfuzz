set -e
git clone-rev.sh https://github.com/ron-rs/ron.git "$PROJECT/repo" 74d35d4b1b1dc56fdf70ce870c6e0faca8a74a98
git -C "$PROJECT/repo" apply "$PROJECT/disable-bench.patch"
