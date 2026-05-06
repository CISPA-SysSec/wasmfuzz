set -e

git clone-rev.sh https://gitlab.com/libtiff/libtiff.git         "$PROJECT/repo"               0cc54883e1092e40ac8de7266178fa5b9b1f1df9
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo "$PROJECT/repo/libjpeg-turbo" afad69dafa6193d838ed075dc34652e646bf745e
git clone-rev.sh https://www.cl.cam.ac.uk/~mgk25/git/jbigkit    "$PROJECT/repo/jbigkit"       7d3c1bea895d910907e2501fe9165e353eceabae --recursive
git clone-rev.sh https://github.com/madler/zlib.git             "$PROJECT/zlib"               f9dd6009be3ed32415edf1e89d1bc38380ecb95d

# git -C "$PROJECT/repo/libjpeg-turbo" apply "$PROJECT/libjpeg-turbo-skip-example.patch"
