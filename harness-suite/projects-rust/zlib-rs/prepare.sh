set -e
git clone-rev.sh https://github.com/trifectatechfoundation/zlib-rs "$PROJECT/repo" b8dfae53b3ed79d07a6259e3fc7e5e47e3f2ef56
git -C "$PROJECT/repo" apply "$PROJECT/fix-inflate-chunked-deflate-loop.patch"
