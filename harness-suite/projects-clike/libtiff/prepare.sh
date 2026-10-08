set -e

git clone-rev.sh https://gitlab.com/libtiff/libtiff.git         "$PROJECT/repo"               0962d91b19f172eba97caf2ee31995a39d99768b
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo "$PROJECT/repo/libjpeg-turbo" dd8ad7915cdf5ab1f8719d488894a5e54c876dd6
git clone-rev.sh https://www.cl.cam.ac.uk/~mgk25/git/jbigkit    "$PROJECT/repo/jbigkit"       4f96ddd9e8850594a2d94fb2201571be0398c8c7 --recursive
git clone-rev.sh https://github.com/madler/zlib.git             "$PROJECT/zlib"               767c4c947852e143f582c85f14cf573411df1b35

# git -C "$PROJECT/repo/libjpeg-turbo" apply "$PROJECT/libjpeg-turbo-skip-example.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-swab-misaligned-size.patch"
