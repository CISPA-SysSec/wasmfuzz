set -e
git clone-rev.sh https://github.com/trifectatechfoundation/zlib-rs "$PROJECT/repo" 049540b605de63a6affc9a1d1f24a1894af2c406
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-inflate-chunked-deflate-loop.patch"
