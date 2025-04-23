set -e
apt-get update -y
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" ea9ff560b4c2086c2f1cae3f02287768a0de4673
git -C "$PROJECT/repo" apply ../wasm_harness_without_entrypoint.patch
