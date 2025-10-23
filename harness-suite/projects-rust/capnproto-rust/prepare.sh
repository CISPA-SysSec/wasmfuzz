set -e
apt-get install -y capnproto

git clone-rev.sh https://github.com/capnproto/capnproto-rust.git "$PROJECT/repo" 635a4e420b75bf247e75312e4e872aa0e7fb9558
