set -e
git clone-rev.sh https://github.com/AFLplusplus/fuzzer-challenges "$PROJECT/repo" 76d42d9b353740ac4dc73ebc9c9360fbe4ede0dc
#git -C "$PROJECT/repo" apply ../fix_link_args.patch
#git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch
