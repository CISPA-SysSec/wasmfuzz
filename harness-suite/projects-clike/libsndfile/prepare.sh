set -e
apt-get update
apt-get install -y autoconf autogen automake libtool pkg-config python3 python-is-python3

git clone-rev.sh https://github.com/libsndfile/libsndfile.git "$PROJECT/repo" 58c05b87162264200b1aa7790be260fd74c9deee
git -C "$PROJECT/repo" apply ../wasm_harness_without_entrypoint.patch
