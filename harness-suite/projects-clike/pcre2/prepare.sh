set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" 315201c36ff0c42e30592f3903becfccf00ebe53
git -C "$PROJECT/repo" apply ../port-fuzzer-no-rlimit-stack.patch

