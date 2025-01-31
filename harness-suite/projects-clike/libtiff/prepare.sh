set -e

git clone-rev.sh https://gitlab.com/libtiff/libtiff.git         "$PROJECT/repo"               fcd4c86c4907d859c3124c8ad786868ba3f0b713
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo "$PROJECT/repo/libjpeg-turbo" e0e18dea5433e600ea92d60814f13efa40a0d7dd
git clone-rev.sh https://www.cl.cam.ac.uk/~mgk25/git/jbigkit    "$PROJECT/repo/jbigkit"       7d3c1bea895d910907e2501fe9165e353eceabae --recursive

git -C "$PROJECT/repo/libjpeg-turbo" apply "$PROJECT/libjpeg-turbo-skip-example.patch"
