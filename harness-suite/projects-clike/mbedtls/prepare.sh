set -e
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y cmake libtool python3 python3-jsonschema python3-jinja2

git clone-rev.sh https://github.com/Mbed-TLS/mbedtls "$PROJECT/repo" 38d4c91b06717483bca17239eebe20befc78b32d --recursive
git -C "$PROJECT/repo" apply ../wasm_stubs.patch
