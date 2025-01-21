set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" e0ea913f11cf64d000556bbf7cb9f8acdf6be4cb
git -C "$PROJECT/repo" apply ../wasi-config.patch
git -C "$PROJECT/repo" apply ../stub-fuzzer-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzzer-hashtable-sequence-of-ops.patch
