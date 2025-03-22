set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make autoconf automake libtool curl tcl tcl-dev
DEBIAN_FRONTEND=noninteractive apt-get install -y clang

git clone-rev.sh https://github.com/sqlite/sqlite "$PROJECT/repo" 62d9d70eddda991bd3dedb55c1beb5a23fb6cae8
