set -e
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" 5d4e649f740c675426fbe4cdaffc53ee2a4cb954
git clone-rev.sh https://github.com/freetype/freetype2-testing.git "$PROJECT/freetype2-testing" 04fa94191645af39750f5eff0a66c49c5cb2c2cc
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 21f74252f2fee6db896e3db80baa3c36663ede62

git -C freetype apply ../freetype2-testing/fuzzing/settings/freetype2/ftoption.patch
git -C freetype apply ../freetype-stub-sjlj.patch
git -C libarchive apply ../libarchive-stubs.patch
