set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y cmake libtool python3 python3-jsonschema python3-jinja2

git clone-rev.sh https://github.com/Mbed-TLS/mbedtls "$PROJECT/repo" 8ab3d8c25d4c364c0423338bdd69bccc61447be2 --recursive
# git -C "$PROJECT/repo" apply ../wasm_stubs.patch
git -C "$PROJECT/repo" apply ../wasm-mbedtls.patch
git -C "$PROJECT/repo/tf-psa-crypto" apply ../../wasm-tf-psa-crypto.patch
