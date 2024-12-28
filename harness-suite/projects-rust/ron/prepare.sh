set -e
git clone-rev.sh https://github.com/ron-rs/ron.git "$PROJECT/repo" 74666478d5553592c6136e0dec12d11bbd10302e
git -C "$PROJECT/repo" apply "$PROJECT/disable-bench.patch"
