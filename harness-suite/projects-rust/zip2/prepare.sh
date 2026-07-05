set -e
git clone-rev.sh https://github.com/zip-rs/zip2.git "$PROJECT/repo" c5caa245147acacd2575b98f7430b7f6eaea3aab
git -C "$PROJECT/repo" apply "$PROJECT/no-jemalloc.patch"
