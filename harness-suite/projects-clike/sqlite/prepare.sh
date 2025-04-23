set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make autoconf automake libtool curl tcl tcl-dev
DEBIAN_FRONTEND=noninteractive apt-get install -y clang

git clone-rev.sh https://github.com/sqlite/sqlite "$PROJECT/repo" dc2d79f80fab9bda99ad95f4c7de752feefa927a
