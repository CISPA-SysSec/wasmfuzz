set -e
apt-get install -y capnproto

git clone-rev.sh https://github.com/capnproto/capnproto-rust.git "$PROJECT/repo" 8037536be5729c0728d93331aaeb82f27c6aa77f
git -C "$PROJECT/repo" apply "$PROJECT/fix-arena-check-offset-overflow.patch"
