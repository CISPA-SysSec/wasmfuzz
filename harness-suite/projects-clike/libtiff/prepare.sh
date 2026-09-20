set -e

git clone-rev.sh https://gitlab.com/libtiff/libtiff.git         "$PROJECT/repo"               0962d91b19f172eba97caf2ee31995a39d99768b
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo "$PROJECT/repo/libjpeg-turbo" b33c60b439d58bc3564d0d32c1bb397fcfb77dc6
git clone-rev.sh https://www.cl.cam.ac.uk/~mgk25/git/jbigkit    "$PROJECT/repo/jbigkit"       4f96ddd9e8850594a2d94fb2201571be0398c8c7 --recursive
git clone-rev.sh https://github.com/madler/zlib.git             "$PROJECT/zlib"               d81c2d7eb705c62294ba03299255672078e89115

# git -C "$PROJECT/repo/libjpeg-turbo" apply "$PROJECT/libjpeg-turbo-skip-example.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-swab-misaligned-size.patch"
