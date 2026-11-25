set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" 01255d7529cd1db9755b661978850faba42b87fb
git -C "$PROJECT/repo" apply ../port-wasi-config.patch
# A fuzzer cannot sign: retry OCSP_basic_verify / CMS_verify without the signature check
# so the signer-chain/issuer checks and the content-digest check stay reachable.
git -C "$PROJECT/repo" apply ../fuzz-x509-ocsp-retry-nosigs.patch
git -C "$PROJECT/repo" apply ../fuzz-cms-verify-retry-no-attr-verify.patch
# Build the library state the first input built lazily (error strings, provider stores) at init.
git -C "$PROJECT/repo" apply ../fuzz-init-lazy-library-state.patch
