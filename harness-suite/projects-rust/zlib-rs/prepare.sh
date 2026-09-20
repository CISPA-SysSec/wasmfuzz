set -e
git clone-rev.sh https://github.com/trifectatechfoundation/zlib-rs "$PROJECT/repo" 7909c0fc48f5d29f6610770e31d6f0c924f9ec3b
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-inflate-chunked-deflate-loop.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-inflate-chunked-output-grow.patch"
