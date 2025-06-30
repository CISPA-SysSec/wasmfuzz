set -e
apt-get install -y capnproto

git clone-rev.sh https://github.com/capnproto/capnproto-rust.git "$PROJECT/repo" fa4cea7fdc09dce522a1e71a5ef44309dee82d42
