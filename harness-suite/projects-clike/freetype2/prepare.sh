set -e
git clone-rev.sh https://gitlab.freedesktop.org/freetype/freetype.git "$PROJECT/freetype" b6bcd2177f72bb4842c7701d7b7f633bb3fc951a
git clone-rev.sh https://github.com/freetype/freetype2-testing.git "$PROJECT/freetype2-testing" db8ae87fead2ede5487e242dd9f5a129ca5e9fd2
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 4b65c3866bc97c72897f00c7b7bb5c993a6de5a4
git clone-rev.sh https://github.com/madler/zlib.git "$PROJECT/zlib" f9dd6009be3ed32415edf1e89d1bc38380ecb95d

git -C freetype apply ../freetype2-testing/fuzzing/settings/freetype2/ftoption.patch
git -C freetype apply ../freetype-stub-sjlj.patch
git -C libarchive apply ../libarchive-stubs.patch
