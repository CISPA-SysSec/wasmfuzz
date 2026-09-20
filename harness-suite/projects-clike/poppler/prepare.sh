set -e

git clone-rev.sh https://gitlab.freedesktop.org/poppler/poppler.git "$PROJECT/repo" aafae2f0bd146810c636e7a4399bee4f6e347354
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" d81c2d7eb705c62294ba03299255672078e89115
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" a69e39ad9ed44818ca316683f6984d25b2a7492b
git -C "$PROJECT/freetype" apply ../port-freetype-wasi-sjlj.patch
git -C "$PROJECT/repo" apply ../port-wasi-fuzzer-init.patch
git -C "$PROJECT/repo" apply ../port-wasi-object-incomplete-type.patch
git -C "$PROJECT/repo" apply ../port-wasi-gfile.patch
git -C "$PROJECT/repo" apply ../port-wasi-fuzzer-temp-file.patch
git -C "$PROJECT/repo" apply ../port-wasi-mutex.patch
git -C "$PROJECT/repo" apply ../fix-fdp-missing-cstdlib.patch
