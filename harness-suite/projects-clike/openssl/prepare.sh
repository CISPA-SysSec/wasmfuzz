set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" d69c014608acdfa37839d49412e6d6974ac539a0
git -C "$PROJECT/repo" apply ../wasi-config.patch
git -C "$PROJECT/repo" apply ../stub-fuzzer-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzzer-hashtable-sequence-of-ops.patch
