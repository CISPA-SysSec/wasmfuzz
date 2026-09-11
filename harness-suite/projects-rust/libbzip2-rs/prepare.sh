set -e
git clone-rev.sh https://github.com/trifectatechfoundation/libbzip2-rs "$PROJECT/repo" 10281317b8c406fec10d9deccc6af100a31941a7
# git -C "$PROJECT/repo" apply "$PROJECT/fuzz-handle-outbuff-full.patch"
