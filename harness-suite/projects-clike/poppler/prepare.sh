set -e

git clone-rev.sh https://gitlab.freedesktop.org/poppler/poppler.git "$PROJECT/repo" eead04e06bbf9168bd995cd55a3b2509aec052fc
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" 5c79d6cd1ac73d70a55f3d963fb568aa32f6d794
git -C "$PROJECT/freetype" apply ../freetype-wasi-sjlj.patch
git -C "$PROJECT/repo" apply ../fix-wasi-fuzzer-init.patch
git -C "$PROJECT/repo" apply ../fix-wasi-object-incomplete-type.patch
git -C "$PROJECT/repo" apply ../fix-wasi-gfile.patch
git -C "$PROJECT/repo" apply ../fix-wasi-fuzzer-temp-file.patch
git -C "$PROJECT/repo" apply ../fix-wasi-mutex.patch
git -C "$PROJECT/repo" apply ../fix-wasi-fdp-cstdlib.patch
