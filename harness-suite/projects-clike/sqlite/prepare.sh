set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make autoconf automake libtool curl tcl tcl-dev
DEBIAN_FRONTEND=noninteractive apt-get install -y clang

git clone-rev.sh https://github.com/sqlite/sqlite "$PROJECT/repo" 7d3a41d1f80e04a7c11245f2bfccbb7c155a972a
