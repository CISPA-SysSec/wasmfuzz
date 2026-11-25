set -e

git clone-rev.sh https://gitlab.com/libtiff/libtiff.git         "$PROJECT/repo"               b2dbe7cbc86860d25acecf658047f46d65959b16
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo "$PROJECT/repo/libjpeg-turbo" 16317632aaee2fad65c979d3c61b0f2ecf6094ec
git clone-rev.sh https://www.cl.cam.ac.uk/~mgk25/git/jbigkit    "$PROJECT/repo/jbigkit"       7b0d5000421a6b4b333781169356adc2e0340479 --recursive
git clone-rev.sh https://github.com/madler/zlib.git             "$PROJECT/zlib"               617e19a81f38c15ff04de9f86882f42ad8a8ffd1

# git -C "$PROJECT/repo/libjpeg-turbo" apply "$PROJECT/libjpeg-turbo-skip-example.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-swab-misaligned-size.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-ccittrlew-word-alignment.patch"
