set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y make autoconf automake libtool curl tcl tcl-dev
DEBIAN_FRONTEND=noninteractive apt-get install -y clang

git clone-rev.sh https://github.com/sqlite/sqlite "$PROJECT/repo" eb6eac655e8650627d47497e642b0c9a83e2dae4
