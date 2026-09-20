set -e

git clone-rev.sh  https://github.com/openssl/openssl.git "$PROJECT/repo" 859aea422b5be17ee9fc0f7678e9de302eb67b72
git -C "$PROJECT/repo" apply ../port-wasi-config.patch
git -C "$PROJECT/repo" apply ../fuzz-stub-error-prints.patch
git -C "$PROJECT/repo" apply ../fuzz-hashtable-sequence-of-ops.patch
git -C "$PROJECT/repo" apply ../fix-fuzzers-missing-stdio.patch
