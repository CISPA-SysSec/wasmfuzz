set -e
apt-get update -y
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" 68f6c16fe1407eff4cdde158566694c3ed666c2f
git -C "$PROJECT/repo" apply ../wasm_harness_without_entrypoint.patch
