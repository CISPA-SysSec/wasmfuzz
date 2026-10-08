set -e

git clone-rev.sh https://github.com/strukturag/libheif "$PROJECT/repo" 5c7b41f3cc097447dd3c700cc9ec7d94fbb59eec
git clone-rev.sh https://github.com/strukturag/libde265 "$PROJECT/libde265" 78bd19905b90a95c2ddbe109b2554ea01f65acd7
git clone-rev.sh https://chromium.googlesource.com/webm/libwebp "$PROJECT/libwebp" 47f95f17201e1721ef31edb1e3c9bdbe2c95d959
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" 767c4c947852e143f582c85f14cf573411df1b35

git -C "$PROJECT/repo" apply ../port-wasi-tmpfile.patch
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-snuc-float-buffer-bounds.patch
git -C "$PROJECT/repo" apply ../limit-fuzzer-memory.patch
