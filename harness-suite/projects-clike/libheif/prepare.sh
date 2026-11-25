set -e

git clone-rev.sh https://github.com/strukturag/libheif "$PROJECT/repo" 12a259a5882dd99d45ec5fc77e296a3b620d1e2e
git clone-rev.sh https://github.com/strukturag/libde265 "$PROJECT/libde265" 4fb298ec1af0686211dc2def73f4f41c2ce19ce5
git clone-rev.sh https://chromium.googlesource.com/webm/libwebp "$PROJECT/libwebp" 1844042d1ca751e62e61df7617dba19c98588339
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" 617e19a81f38c15ff04de9f86882f42ad8a8ffd1

git -C "$PROJECT/repo" apply ../port-wasi-tmpfile.patch
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-snuc-float-buffer-bounds.patch
git -C "$PROJECT/repo" apply ../limit-fuzzer-memory.patch
git -C "$PROJECT/repo" apply ../fix-tili-unsupported-tile-codec.patch
