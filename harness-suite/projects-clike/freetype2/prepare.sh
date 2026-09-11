set -e
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" 5c79d6cd1ac73d70a55f3d963fb568aa32f6d794
git clone-rev.sh https://github.com/freetype/freetype2-testing.git "$PROJECT/freetype2-testing" db8ae87fead2ede5487e242dd9f5a129ca5e9fd2
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 7b0ecd5af8689a0bc5df358cd6289aab0f266183
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca

git -C freetype apply ../freetype2-testing/fuzzing/settings/freetype2/ftoption.patch
git -C freetype apply ../port-freetype-wasi-sjlj.patch
git -C libarchive apply ../port-libarchive-stubs.patch
