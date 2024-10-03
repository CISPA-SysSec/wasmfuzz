set -e

git clone-rev.sh https://github.com/PCRE2Project/pcre2 "$PROJECT/repo" c49e596481e6c793a5d3c91c724ad4de0f97cd15
git -C "$PROJECT/repo" apply ../fuzzer-dont-rlimit-stack.patch

