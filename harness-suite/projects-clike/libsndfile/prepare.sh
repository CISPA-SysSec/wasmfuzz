set -e
apt-get update -y
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" 396a715daeae7316f047ee220b364ab983b66df4
git -C "$PROJECT/repo" apply ../port-harness-link-flags.patch
git -C "$PROJECT/repo" apply ../fix-wavlike-list-subchunk-size-wrap.patch
