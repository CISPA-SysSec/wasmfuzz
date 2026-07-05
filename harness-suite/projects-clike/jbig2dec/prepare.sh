set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make libtool pkg-config vim libreadline-dev wget autoconf

git clone-rev.sh git://git.ghostscript.com/jbig2dec.git "$PROJECT/repo" dc15c39bbbddc90f79c14563d2eb5a794106be8f --recursive
