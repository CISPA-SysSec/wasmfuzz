set -e

git clone-rev.sh https://gitlab.freedesktop.org/poppler/poppler.git "$PROJECT/repo" 34fbdfcf97868e398a963bb6576a5343c89ff1c9
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" 656cb777798fa420a13faba3758779e9ed6c4798
git -C "$PROJECT/freetype" apply ../freetype-wasi-sjlj.patch
git -C "$PROJECT/repo" apply ../fix-wasi-fuzzer-init.patch
git -C "$PROJECT/repo" apply ../fix-wasi-object-incomplete-type.patch
git -C "$PROJECT/repo" apply ../fix-wasi-gfile.patch
git -C "$PROJECT/repo" apply ../fix-wasi-fuzzer-temp-file.patch
git -C "$PROJECT/repo" apply ../fix-wasi-mutex.patch
