set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y cmake libtool python3 python3-jsonschema python3-jinja2

git clone-rev.sh https://github.com/Mbed-TLS/mbedtls "$PROJECT/repo" 45ad2fc5ee6e5ca2a7236f44e88275038d870464 --recursive
# git -C "$PROJECT/repo" apply ../wasm_stubs.patch
git -C "$PROJECT/repo" apply ../wasm-mbedtls.patch
git -C "$PROJECT/repo/tf-psa-crypto" apply ../../wasm-tf-psa-crypto.patch
