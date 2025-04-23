set -e
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" ccabe7ac02c688d26d1753bafe80f5a2b00c479a
git clone-rev.sh https://github.com/freetype/freetype2-testing.git "$PROJECT/freetype2-testing" 04fa94191645af39750f5eff0a66c49c5cb2c2cc
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" dcbf1e0ededa95849f098d154a25876ed5754bcf

git -C freetype apply ../freetype2-testing/fuzzing/settings/freetype2/ftoption.patch
git -C freetype apply ../freetype-stub-sjlj.patch
git -C libarchive apply ../libarchive-stubs.patch
