set -e
apt-get install -y capnproto

git clone-rev.sh https://github.com/capnproto/capnproto-rust.git "$PROJECT/repo" 033d4833964589ce9029c59ef868389f51c68d03
