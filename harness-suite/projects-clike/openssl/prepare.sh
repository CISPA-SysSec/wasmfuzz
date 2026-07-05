set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" bf41baa2bf3215625d44f7c0dc438ab1b2e3a3d0
git -C "$PROJECT/repo" apply ../wasi-config.patch
git -C "$PROJECT/repo" apply ../stub-fuzzer-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzzer-hashtable-sequence-of-ops.patch
git -C "$PROJECT/repo" apply ../fuzzers-stdio-h.patch
