set -e
git clone-rev.sh https://github.com/ron-rs/ron.git "$PROJECT/repo" abc60f50327dfb32c45e9f2d73463b6fe52d7e4e
git -C "$PROJECT/repo" apply "$PROJECT/disable-bench.patch"
