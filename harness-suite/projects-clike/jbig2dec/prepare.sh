set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make libtool pkg-config vim libreadline-dev wget autoconf

git clone-rev.sh git://git.ghostscript.com/jbig2dec.git "$PROJECT/repo" 6ecb04980813d693234190021bd1cf874c05b1b4 --recursive
