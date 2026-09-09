set -e
git clone-rev.sh https://github.com/AFLplusplus/fuzzer-challenges "$PROJECT/repo" 6d0766f2c6dcf785c46b8f6824a8f1eb93a6fef0
#git -C "$PROJECT/repo" apply ../fix_link_args.patch
#git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch
