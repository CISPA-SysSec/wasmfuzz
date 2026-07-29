set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" 971b8d060e52499d6ffd2f9ca697fe23f72a629a
git -C "$PROJECT/repo" apply ../wasi-config.patch
git -C "$PROJECT/repo" apply ../stub-fuzzer-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzzer-hashtable-sequence-of-ops.patch
git -C "$PROJECT/repo" apply ../fuzzers-stdio-h.patch
