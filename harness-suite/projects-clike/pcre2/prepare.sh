set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" aac57f978e38fb4a04899d623b68e0fbb5bcaf6c
git -C "$PROJECT/repo" apply ../port-fuzzer-no-rlimit-stack.patch

