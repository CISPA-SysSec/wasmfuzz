set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" d8f792f2fa7d23c592d8351e6ab7bd0f9c24f58a
git -C "$PROJECT/repo" apply ../port-wasi-config.patch
git -C "$PROJECT/repo" apply ../fuzz-hashtable-sequence-of-ops.patch
# A fuzzer cannot sign: retry OCSP_basic_verify / CMS_verify without the signature check
# so the signer-chain/issuer checks and the content-digest check stay reachable.
git -C "$PROJECT/repo" apply ../fuzz-x509-ocsp-retry-nosigs.patch
git -C "$PROJECT/repo" apply ../fuzz-cms-verify-retry-no-attr-verify.patch
