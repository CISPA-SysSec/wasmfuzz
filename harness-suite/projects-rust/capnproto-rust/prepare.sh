set -e
apt-get install -y capnproto

git clone-rev.sh https://github.com/capnproto/capnproto-rust.git "$PROJECT/repo" 61f2c7640516f6d74c4b7d6e67257fae4fff9bda
