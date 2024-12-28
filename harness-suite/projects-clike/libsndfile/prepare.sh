set -e
apt-get update
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" 0d3f80b7394368623df558d8ba3fee6348584d4d
git -C "$PROJECT/repo" apply ../wasm_harness_without_entrypoint.patch
