set -e
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y cmake libtool python3 python3-jsonschema python3-jinja2

git clone-rev.sh https://github.com/Mbed-TLS/mbedtls "$PROJECT/repo" e1f37c58a2011ec9f6cd9ccf1dfffec3c2501662 --recursive
git -C "$PROJECT/repo" apply ../wasm_stubs.patch
