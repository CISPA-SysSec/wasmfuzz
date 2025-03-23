set -e
apt-get update -y
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" 17a19ab264fcf238f46104cea9af9a0a5ca3786d
git -C "$PROJECT/repo" apply ../wasm_harness_without_entrypoint.patch
