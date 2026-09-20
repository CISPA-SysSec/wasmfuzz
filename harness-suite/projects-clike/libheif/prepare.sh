set -e

git clone-rev.sh https://github.com/strukturag/libheif "$PROJECT/repo" 9ef7b5ddb80afd20037bba00834d6799544d94ae
git clone-rev.sh https://github.com/strukturag/libde265 "$PROJECT/libde265" 78bd19905b90a95c2ddbe109b2554ea01f65acd7
git clone-rev.sh https://chromium.googlesource.com/webm/libwebp "$PROJECT/libwebp" ea0c620525401803b2024390321a6cb1cccbfc57
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" d81c2d7eb705c62294ba03299255672078e89115

git -C "$PROJECT/repo" apply ../port-wasi-tmpfile.patch
git -C "$PROJECT/repo" apply ../port-wasi-threads.patch
git -C "$PROJECT/repo" apply ../fix-snuc-float-buffer-bounds.patch
git -C "$PROJECT/repo" apply ../limit-fuzzer-memory.patch
