set -e
git clone-rev.sh https://github.com/zip-rs/zip2.git "$PROJECT/repo" 6c4fe6fb72857cbaef75b6c768f6dea05b4ddc38
git -C "$PROJECT/repo" apply "$PROJECT/no-jemalloc.patch"
