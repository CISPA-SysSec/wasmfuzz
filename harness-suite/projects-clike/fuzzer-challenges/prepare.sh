set -e
git clone-rev.sh https://github.com/AFLplusplus/fuzzer-challenges "$PROJECT/repo" 27cd8a6e95bc02985e260757cc47771169a3613f
#git -C "$PROJECT/repo" apply ../fix_link_args.patch
#git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch
