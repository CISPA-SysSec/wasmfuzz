set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make libtool pkg-config vim libreadline-dev wget autoconf

git clone-rev.sh git://git.ghostscript.com/jbig2dec.git "$PROJECT/repo" b5250e7767930e68c31218fdfcddda14c8bd0f33 --recursive
