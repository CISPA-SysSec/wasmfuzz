set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" b790e021cb922b1df2adffe9bf5f63210584be1f
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

