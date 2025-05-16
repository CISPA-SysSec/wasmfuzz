set -e
git clone-rev.sh https://github.com/trifectatechfoundation/zlib-rs "$PROJECT/repo" 39838838ec2d49021548f90cec60cc3d8f56b188 
git -C "$PROJECT/repo" apply "$PROJECT/compress-length-u32-u64.patch"
