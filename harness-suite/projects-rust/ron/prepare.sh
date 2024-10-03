set -e
git clone-rev.sh https://github.com/ron-rs/ron.git "$PROJECT/repo" ea6b40619c92a9663883cf7c45c0876734a2fcf5
git -C "$PROJECT/repo" apply "$PROJECT/disable-bench.patch"
