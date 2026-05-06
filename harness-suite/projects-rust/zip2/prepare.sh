set -e
git clone-rev.sh https://github.com/zip-rs/zip2.git "$PROJECT/repo" 905f661b9f8e46d0fd5935a5696ad93548d48fe8
git -C "$PROJECT/repo" apply "$PROJECT/no-jemalloc.patch"
