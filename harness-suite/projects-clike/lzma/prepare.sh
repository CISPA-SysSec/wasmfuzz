set -e
DEBIAN_FRONTEND=noninteractive apt-get install -y autoconf automake libtool make zip
git clone-rev.sh https://github.com/fancycode/lzma-fuzz.git "$PROJECT/repo" d25e63d8f6b8186d04146cb19405bc5ad565412e
git -C "$PROJECT/repo" apply ../limit_allocs_more.patch
git -C "$PROJECT/repo" apply ../stub-crc-for-fuzzing.patch
