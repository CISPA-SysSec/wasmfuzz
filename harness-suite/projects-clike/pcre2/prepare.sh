set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" ff92e0b9cea5b5ae3af12ba930d03556684f098b
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

