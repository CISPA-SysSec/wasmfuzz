set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" 5857bdbb766a206f4efe7e8c72cf6721a625bd90
git -C "$PROJECT/repo" apply ../wasi-config.patch
git -C "$PROJECT/repo" apply ../stub-fuzzer-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzzer-hashtable-sequence-of-ops.patch
git -C "$PROJECT/repo" apply ../fuzzers-stdio-h.patch
