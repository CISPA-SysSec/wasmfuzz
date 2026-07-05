set -e

git clone-rev.sh https://gitlab.com/libtiff/libtiff.git         "$PROJECT/repo"               b40dc6ec4997d4d2e62152fe62dac20c3a23f557
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo "$PROJECT/repo/libjpeg-turbo" 01d607bd618334ccb5bfdd7e1891dda11d58036c
git clone-rev.sh https://www.cl.cam.ac.uk/~mgk25/git/jbigkit    "$PROJECT/repo/jbigkit"       4f96ddd9e8850594a2d94fb2201571be0398c8c7 --recursive
git clone-rev.sh https://github.com/madler/zlib.git             "$PROJECT/zlib"               e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca

# git -C "$PROJECT/repo/libjpeg-turbo" apply "$PROJECT/libjpeg-turbo-skip-example.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-swab24-misaligned-size.patch"
