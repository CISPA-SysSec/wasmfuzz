set -e
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y cmake libtool python3 python3-jsonschema python3-jinja2

git clone-rev.sh https://github.com/Mbed-TLS/mbedtls "$PROJECT/repo" 6daf4ef507f3dffce4f8bbd70448c98c2919c622 --recursive
# git -C "$PROJECT/repo" apply ../wasm_stubs.patch
git -C "$PROJECT/repo" apply ../wasm-mbedtls.patch
git -C "$PROJECT/repo/tf-psa-crypto" apply ../../wasm-tf-psa-crypto.patch
