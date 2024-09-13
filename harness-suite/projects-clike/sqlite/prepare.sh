set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make autoconf automake libtool curl tcl tcl-dev

git clone-rev.sh https://github.com/sqlite/sqlite "$PROJECT/repo" d888e79bb8a8efc75245fe337fd1d6c4d6266b31
