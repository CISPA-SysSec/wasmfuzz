set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" 5db7b99914c9a13798e9d7783a02e68ae7e411d8
git -C "$PROJECT/repo" apply ../wasi-config.patch
git -C "$PROJECT/repo" apply ../stub-fuzzer-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzzer-hashtable-sequence-of-ops.patch
git -C "$PROJECT/repo" apply ../fuzzers-stdio-h.patch
