set -e
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y cmake libtool python3 python3-jsonschema python3-jinja2

git clone-rev.sh https://github.com/Mbed-TLS/mbedtls "$PROJECT/repo" 03e704018ad7e005648f5ca428bc095e4ce3b5a0 --recursive
# git -C "$PROJECT/repo" apply ../wasm_stubs.patch
git -C "$PROJECT/repo" apply ../wasm-mbedtls.patch
git -C "$PROJECT/repo/tf-psa-crypto" apply ../../wasm-tf-psa-crypto.patch
