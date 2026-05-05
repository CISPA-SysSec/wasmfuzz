set -e
git clone-rev.sh https://github.com/AFLplusplus/fuzzer-challenges "$PROJECT/repo" 0aa10845369477e95dd2eed7bd0075a1de531d0c
#git -C "$PROJECT/repo" apply ../fix_link_args.patch
#git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch
