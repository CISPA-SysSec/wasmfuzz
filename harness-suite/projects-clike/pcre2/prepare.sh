set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" 3cd3e92fb362a256bbaadbab95326dec2d6928dd
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

