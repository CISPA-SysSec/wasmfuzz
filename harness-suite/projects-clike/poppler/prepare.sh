set -e

git clone-rev.sh https://gitlab.freedesktop.org/poppler/poppler.git "$PROJECT/repo" 0c9cf7ce6ece57046cf8d77a0153bff661791616
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" 767c4c947852e143f582c85f14cf573411df1b35
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" d333439633039de426f943f28a2926c7f97b5ae5
git -C "$PROJECT/freetype" apply ../port-freetype-wasi-sjlj.patch
git -C "$PROJECT/repo" apply ../port-wasi-fuzzer-init.patch
git -C "$PROJECT/repo" apply ../port-wasi-object-incomplete-type.patch
git -C "$PROJECT/repo" apply ../port-wasi-gfile.patch
git -C "$PROJECT/repo" apply ../port-wasi-fuzzer-temp-file.patch
git -C "$PROJECT/repo" apply ../port-wasi-mutex.patch
git -C "$PROJECT/repo" apply ../fix-fdp-missing-cstdlib.patch
