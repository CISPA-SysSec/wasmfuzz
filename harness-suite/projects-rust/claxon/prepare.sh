set -e
git clone-rev.sh https://github.com/ruuda/claxon.git "$PROJECT/repo" 5fcd0c1cf66fd182cd21360d8a630312f27036dd
git -C "$PROJECT/repo" apply "$PROJECT/0001-update-fuzzers.patch"
