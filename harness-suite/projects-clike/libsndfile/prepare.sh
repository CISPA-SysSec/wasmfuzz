set -e
apt-get update -y
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" b9103bd48b6c8fb517ae737fe3baee0c718b804c
git -C "$PROJECT/repo" apply ../port-harness-link-flags.patch
