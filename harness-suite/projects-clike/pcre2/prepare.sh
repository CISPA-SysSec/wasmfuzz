set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" 1e09555d6950bfcf83bd98fa597b0c6440d43c9c
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

