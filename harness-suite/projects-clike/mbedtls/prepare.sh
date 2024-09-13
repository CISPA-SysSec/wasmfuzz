set -e
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y cmake libtool python3 python3-jsonschema python3-jinja2

git clone-rev.sh https://github.com/Mbed-TLS/mbedtls "$PROJECT/repo" a7c9c18eb9bfe7fb12db11b081898fe461d49b09 --recursive
git -C "$PROJECT/repo" apply ../wasm_stubs.patch
