set -e

git clone-rev.sh https://gitlab.com/libtiff/libtiff.git         "$PROJECT/repo"               732665c2c8785cec3e1f46ba9908575f0f3a8059
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo "$PROJECT/repo/libjpeg-turbo" 94d5ff43ca91e7e69c984fed0ec0141b5fbd19b3
git clone-rev.sh https://www.cl.cam.ac.uk/~mgk25/git/jbigkit    "$PROJECT/repo/jbigkit"       4f96ddd9e8850594a2d94fb2201571be0398c8c7 --recursive
git clone-rev.sh https://github.com/madler/zlib.git             "$PROJECT/zlib"               e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca

# git -C "$PROJECT/repo/libjpeg-turbo" apply "$PROJECT/libjpeg-turbo-skip-example.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-swab24-misaligned-size.patch"
