set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" 0ed421c00eeb0802c1428fab092d8c9b10fa6a6d
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

