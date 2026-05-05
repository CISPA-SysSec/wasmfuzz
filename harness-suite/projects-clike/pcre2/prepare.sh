set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" 4f460e5edaa698bda57a93e044ca811fe64e93f8
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

