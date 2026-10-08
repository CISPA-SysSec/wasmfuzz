set -e
# Chromium's zlib fork (exported mirror of chromium/src/third_party/zlib), upstream HEAD.
git clone-rev.sh https://chromium.googlesource.com/chromium/src/third_party/zlib "$PROJECT/repo" 456ae730017b9b4bd3371927abc82627fd51feef
