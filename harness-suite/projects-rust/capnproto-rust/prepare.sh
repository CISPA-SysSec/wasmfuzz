set -e
apt-get install -y capnproto

git clone-rev.sh https://github.com/capnproto/capnproto-rust.git "$PROJECT/repo" afab132ef512c2f91107a250cdbe1f9644051a70
git -C "$PROJECT/repo" apply "$PROJECT/fix-arena-check-offset-overflow.patch"
