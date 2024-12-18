set -e
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" 94cb3a2eb96b3f17a1a3bd0e6f7da97c0e1d8f57
git clone-rev.sh https://github.com/freetype/freetype2-testing.git "$PROJECT/freetype2-testing" 57d875f1c45b5c9b83bf2e99cedc150108a2b28c
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 40ff837717b89e9a5d2c735758f503d124d17b72

git -C freetype apply ../freetype2-testing/fuzzing/settings/freetype2/ftoption.patch
git -C freetype apply ../freetype-stub-sjlj.patch
git -C libarchive apply ../libarchive-stubs.patch
