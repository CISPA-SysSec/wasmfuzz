set -e
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" b1f47850878d232eea372ab167e760ccac4c4e32
git clone-rev.sh https://github.com/freetype/freetype2-testing.git "$PROJECT/freetype2-testing" 04fa94191645af39750f5eff0a66c49c5cb2c2cc
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 65196fdd1a385f22114f245a9002ee8dc899f2c4

git -C freetype apply ../freetype2-testing/fuzzing/settings/freetype2/ftoption.patch
git -C freetype apply ../freetype-stub-sjlj.patch
git -C libarchive apply ../libarchive-stubs.patch
