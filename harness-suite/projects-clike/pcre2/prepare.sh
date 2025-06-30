set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" bf50eeef64fc4f5ddfc93a041e2f4d7357f3c431
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

