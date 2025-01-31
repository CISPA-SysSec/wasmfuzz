set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" 804b10a5727668e4e66a1c13839be4beeda7ed16
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

