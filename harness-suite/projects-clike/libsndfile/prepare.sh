set -e
apt-get update
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" c53552a06f8e6cd41fc683a1aefef5884306d1a5
git -C "$PROJECT/repo" apply ../wasm_harness_without_entrypoint.patch
