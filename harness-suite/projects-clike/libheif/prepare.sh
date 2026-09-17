set -e

git clone-rev.sh https://github.com/strukturag/libheif "$PROJECT/repo" e0f961366c1de0291c8afdddbb1d5c94d9189342
git clone-rev.sh https://github.com/strukturag/libde265 "$PROJECT/libde265" ac13dcd5b8f86a1772e467c2c0967dbd812d8818
git clone-rev.sh https://chromium.googlesource.com/webm/libwebp "$PROJECT/libwebp" 9c4a699e5aacc1995a27ca3bf1643c8b2378616c
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca

git -C "$PROJECT/repo" apply ../port-wasi-tmpfile.patch
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-snuc-float-buffer-bounds.patch
