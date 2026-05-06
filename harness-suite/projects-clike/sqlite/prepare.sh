set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make autoconf automake libtool curl tcl tcl-dev
DEBIAN_FRONTEND=noninteractive apt-get install -y clang

git clone-rev.sh https://github.com/sqlite/sqlite "$PROJECT/repo" d4c4e91674862650014e605d8a082146b8572003
