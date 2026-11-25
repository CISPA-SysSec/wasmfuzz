set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" 0705b4a358eca084a1e6159efa29cbf6d3aea095
git -C "$PROJECT/repo" apply ../port-fuzzer-no-rlimit-stack.patch

