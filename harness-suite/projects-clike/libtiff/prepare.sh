set -e

git clone-rev.sh https://gitlab.com/libtiff/libtiff.git         "$PROJECT/repo"               0f5b81947b3a7d19a20d840f384dcb341d998722
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo "$PROJECT/repo/libjpeg-turbo" 51cee0362998ec6f1eabac1e795f3b6e3ee639ea
git clone-rev.sh https://www.cl.cam.ac.uk/~mgk25/git/jbigkit    "$PROJECT/repo/jbigkit"       7d3c1bea895d910907e2501fe9165e353eceabae --recursive

git -C "$PROJECT/repo/libjpeg-turbo" apply "$PROJECT/libjpeg-turbo-skip-example.patch"
