set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" d8f792f2fa7d23c592d8351e6ab7bd0f9c24f58a
git -C "$PROJECT/repo" apply ../port-wasi-config.patch
git -C "$PROJECT/repo" apply ../fuzz-stub-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzz-hashtable-sequence-of-ops.patch
git -C "$PROJECT/repo" apply ../fix-fuzzers-missing-stdio.patch
