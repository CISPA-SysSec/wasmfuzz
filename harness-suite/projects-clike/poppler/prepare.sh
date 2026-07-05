set -e

git clone-rev.sh https://gitlab.freedesktop.org/poppler/poppler.git "$PROJECT/repo" 2c64135f5d28018594040d847d2a296a598786ac
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" 25a08f24cfc0da879d1938352d026532f280b77e
git -C "$PROJECT/freetype" apply ../freetype-wasi-sjlj.patch
git -C "$PROJECT/repo" apply ../fix-wasi-fuzzer-init.patch
git -C "$PROJECT/repo" apply ../fix-wasi-object-incomplete-type.patch
git -C "$PROJECT/repo" apply ../fix-wasi-gfile.patch
git -C "$PROJECT/repo" apply ../fix-wasi-fuzzer-temp-file.patch
git -C "$PROJECT/repo" apply ../fix-wasi-mutex.patch
