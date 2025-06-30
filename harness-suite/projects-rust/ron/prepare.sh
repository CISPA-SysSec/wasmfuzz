set -e
git clone-rev.sh https://github.com/ron-rs/ron.git "$PROJECT/repo" 27a26d691a24ac1eef3462086eed31dcbc0196f9
git -C "$PROJECT/repo" apply "$PROJECT/disable-bench.patch"
