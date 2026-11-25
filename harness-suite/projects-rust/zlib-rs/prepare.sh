set -e
git clone-rev.sh https://github.com/trifectatechfoundation/zlib-rs "$PROJECT/repo" f59d16f6f09b1669cc4d6f1ffa9a54e6e11577f5
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-inflate-chunked-deflate-loop.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-inflate-chunked-output-grow.patch"
