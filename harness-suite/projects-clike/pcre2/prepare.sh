set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" 413bd8a6ee6d98497d73ff992350050c2947a1f7
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

