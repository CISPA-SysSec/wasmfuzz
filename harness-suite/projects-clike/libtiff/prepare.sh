set -e

git clone-rev.sh https://gitlab.com/libtiff/libtiff.git         "$PROJECT/repo"               d6217f352cd5eb388a72e44053c985ec15b3375a
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo "$PROJECT/repo/libjpeg-turbo" c082e8697dfc4b6f8e2eacf0a23e41d98004ba65
git clone-rev.sh https://www.cl.cam.ac.uk/~mgk25/git/jbigkit    "$PROJECT/repo/jbigkit"       4f96ddd9e8850594a2d94fb2201571be0398c8c7 --recursive
git clone-rev.sh https://github.com/madler/zlib.git             "$PROJECT/zlib"               e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca

# git -C "$PROJECT/repo/libjpeg-turbo" apply "$PROJECT/libjpeg-turbo-skip-example.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-swab24-misaligned-size.patch"
