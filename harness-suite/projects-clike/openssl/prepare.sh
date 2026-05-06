set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" 945cc69f5448b9da2a0ae8ac1e55efa45a442d12
git -C "$PROJECT/repo" apply ../wasi-config.patch
git -C "$PROJECT/repo" apply ../stub-fuzzer-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzzer-hashtable-sequence-of-ops.patch
git -C "$PROJECT/repo" apply ../fuzzers-stdio-h.patch
