set -e
# Chromium's zlib fork (exported mirror of chromium/src/third_party/zlib), upstream HEAD.
git clone-rev.sh https://chromium.googlesource.com/chromium/src/third_party/zlib "$PROJECT/repo" 401d1853956d408bfd327ee5e54c1c7b67086f87
