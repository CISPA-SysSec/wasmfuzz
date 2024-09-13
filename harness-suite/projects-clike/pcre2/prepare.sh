set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" 7a0eda1f66e61602d66e850dfeeb70a266230b4c
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

