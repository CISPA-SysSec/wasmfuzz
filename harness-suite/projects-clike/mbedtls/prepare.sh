set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y cmake libtool python3 python3-jsonschema python3-jinja2

git clone-rev.sh https://github.com/Mbed-TLS/mbedtls "$PROJECT/repo" 7ad26d3bf091855fbe37f3ab2ea61f4e99461ef3 --recursive
# git -C "$PROJECT/repo" apply ../wasm_stubs.patch
git -C "$PROJECT/repo" apply ../port-fuzz-link-args.patch
git -C "$PROJECT/repo/tf-psa-crypto" apply ../../port-wasi-time-entropy.patch
