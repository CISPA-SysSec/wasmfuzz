set -e
git clone-rev.sh https://github.com/trifectatechfoundation/zlib-rs "$PROJECT/repo" 5a82af8a944d3b2d23e861c5438bac35bc40d16d
git -C "$PROJECT/repo" apply "$PROJECT/fix-inflate-chunked-deflate-loop.patch"
