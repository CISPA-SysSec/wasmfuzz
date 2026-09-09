set -e
apt-get install -y capnproto

git clone-rev.sh https://github.com/capnproto/capnproto-rust.git "$PROJECT/repo" 81bc1b815d0f450c9114f9cc2e2274182d210df2
git -C "$PROJECT/repo" apply "$PROJECT/fix-arena-check-offset-overflow.patch"
