set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" 3d3bb26a13dcc67f99e66de6a44ae9ced117f64b
git -C "$PROJECT/repo" apply ../wasi-config.patch
git -C "$PROJECT/repo" apply ../stub-fuzzer-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzzer-hashtable-sequence-of-ops.patch
