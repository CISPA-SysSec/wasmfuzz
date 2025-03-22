set -e

apt install -y capnproto

git clone-rev.sh https://github.com/capnproto/capnproto-rust.git "$PROJECT/repo" e4fc3697c6937c7454079f86018f9ba90296eb8f
