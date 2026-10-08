set -e
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" 032c3c5c80a8fc2aad8258a13526dfcbcc0d8dce
git clone-rev.sh https://github.com/freetype/freetype2-testing.git "$PROJECT/freetype2-testing" db8ae87fead2ede5487e242dd9f5a129ca5e9fd2
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" caacb791cc9487eacc2a8826875871a77f57bdf0
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" d81c2d7eb705c62294ba03299255672078e89115

git -C freetype apply ../freetype2-testing/fuzzing/settings/freetype2/ftoption.patch
git -C freetype apply ../port-freetype-wasi-sjlj.patch
git -C libarchive apply ../port-libarchive-stubs.patch
git -C libarchive apply ../fix-stale-errno-in-string-conversion.patch
