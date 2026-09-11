set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" 3c63230c7c90ce1c157e45f2e2c2d4b803d02475
git -C "$PROJECT/repo" apply ../port-wasi-config.patch
git -C "$PROJECT/repo" apply ../fuzz-stub-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzz-hashtable-sequence-of-ops.patch
git -C "$PROJECT/repo" apply ../fix-fuzzers-missing-stdio.patch
