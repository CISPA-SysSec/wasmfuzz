set -e
apt-get update -y
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" 52b803f57a1f4d23471f5c5f77e1a21e0721ea0e
git -C "$PROJECT/repo" apply ../wasm_harness_without_entrypoint.patch
