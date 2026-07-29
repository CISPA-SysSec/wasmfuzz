set -e
apt-get update -y
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" 8795cc078ea37d1c18e341d8e8e2f0abc8681a79
git -C "$PROJECT/repo" apply ../wasm_harness_without_entrypoint.patch
