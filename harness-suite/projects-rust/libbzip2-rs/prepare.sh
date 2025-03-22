set -e
git clone-rev.sh https://github.com/trifectatechfoundation/libbzip2-rs "$PROJECT/repo" ed9e9c302a498024b7e96e920c704278b1da7866
git -C "$PROJECT/repo" apply "$PROJECT/harnesses-handle-outbuff-full.patch"
