set -e
git clone-rev.sh https://github.com/trifectatechfoundation/zlib-rs "$PROJECT/repo" 5e4e5beee010e5466a088558e2bd1377a7f11171
git -C "$PROJECT/repo" apply "$PROJECT/fix-inflate-chunked-deflate-loop.patch"
