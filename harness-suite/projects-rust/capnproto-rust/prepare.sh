set -e

apt install -y capnproto

git clone-rev.sh https://github.com/capnproto/capnproto-rust.git "$PROJECT/repo" ffcb213b6223d0d25ee5f622c9842b3c5a1f78ba
