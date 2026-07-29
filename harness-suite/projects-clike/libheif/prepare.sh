set -e

git clone-rev.sh https://github.com/strukturag/libheif "$PROJECT/repo" 1a3583bcce77de6d3f8701c0758e3954863681ba
git clone-rev.sh https://github.com/strukturag/libde265 "$PROJECT/libde265" 4d45a6b36767318237771e1b3faf41773c4af4ad
git clone-rev.sh https://chromium.googlesource.com/webm/libwebp "$PROJECT/libwebp" 733c91e461c18cf1127c9ed0a80dccbcfed599d3
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca

git -C "$PROJECT/repo" apply ../fix-wasi-tmpfile.patch
git -C "$PROJECT/repo" apply ../fix-wasi-threads.patch
