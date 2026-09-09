set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" 3c63230c7c90ce1c157e45f2e2c2d4b803d02475
git -C "$PROJECT/repo" apply ../wasi-config.patch
git -C "$PROJECT/repo" apply ../stub-fuzzer-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzzer-hashtable-sequence-of-ops.patch
git -C "$PROJECT/repo" apply ../fuzzers-stdio-h.patch
