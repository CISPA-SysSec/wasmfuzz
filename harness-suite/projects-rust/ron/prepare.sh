set -e
git clone-rev.sh https://github.com/ron-rs/ron.git "$PROJECT/repo" b7282547372b216d83e2055ae616243f5924ed6b
git -C "$PROJECT/repo" apply "$PROJECT/disable-bench.patch"
