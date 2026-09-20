set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" c73daa9603a8d0b64e90e4048c8c2f7f56b3a930
git -C "$PROJECT/repo" apply ../port-fuzzer-no-rlimit-stack.patch

