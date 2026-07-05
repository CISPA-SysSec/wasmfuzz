set -e

git clone-rev.sh https://github.com/strukturag/libheif "$PROJECT/repo" b2011bbc721304d3cf4cb74259340b9484dacb08
git clone-rev.sh https://github.com/strukturag/libde265 "$PROJECT/libde265" d223194b0bb9bf950d894d27ccc46d08941efa1b
git clone-rev.sh https://chromium.googlesource.com/webm/libwebp "$PROJECT/libwebp" 3757b8afeb54e305eaef18502812a9a88b7ed662
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca

git -C "$PROJECT/repo" apply ../fix-wasi-tmpfile.patch
git -C "$PROJECT/repo" apply ../fix-wasi-threads.patch
