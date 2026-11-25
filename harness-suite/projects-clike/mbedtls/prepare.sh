set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y cmake libtool python3 python3-jsonschema python3-jinja2

git clone-rev.sh https://github.com/Mbed-TLS/mbedtls "$PROJECT/repo" 0e2cc5fdac71ffbddb4b463189b042f8d7a5cf35 --recursive
# git -C "$PROJECT/repo" apply ../wasm_stubs.patch
git -C "$PROJECT/repo" apply ../port-fuzz-link-args.patch
# CA parsing validates EC keys through PSA, which fails before psa_crypto_init(): every
# client input returned 1 (upstream programs/fuzz still has this order, 2026-10).
git -C "$PROJECT/repo" apply ../fuzz-client-psa-init-order.patch
# The X.509 fuzzers seeded PSA (entropy + CTR_DRBG) and freed it again for every input.
git -C "$PROJECT/repo" apply ../fuzz-x509-psa-init-once.patch
# fuzz_server parsed its certificate and key for the first input only, then freed them.
git -C "$PROJECT/repo" apply ../fuzz-server-cert-key-once.patch
git -C "$PROJECT/repo/tf-psa-crypto" apply ../../port-wasi-time-entropy.patch
