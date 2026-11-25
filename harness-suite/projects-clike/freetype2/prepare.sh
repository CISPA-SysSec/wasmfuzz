set -e
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" d4d00b890aab5970f291338b9de626ceafefbdec
git clone-rev.sh https://github.com/freetype/freetype2-testing.git "$PROJECT/freetype2-testing" db8ae87fead2ede5487e242dd9f5a129ca5e9fd2
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" c6a3eaa4c4aecc3b58795ec58899ea0b1366a45f
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" 617e19a81f38c15ff04de9f86882f42ad8a8ffd1

git -C freetype apply ../freetype2-testing/fuzzing/settings/freetype2/ftoption.patch
git -C freetype apply ../port-freetype-wasi-sjlj.patch
git -C freetype apply ../fix-freetype-t42-glyph-index-bounds.patch
git -C libarchive apply ../port-libarchive-stubs.patch
