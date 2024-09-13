set -e
git clone-rev.sh https://github.com/ruuda/claxon.git "$PROJECT/repo" 20fd6a78830ec75918175b2375c21dd667b894ce
git -C "$PROJECT/repo" apply "$PROJECT/0001-update-fuzzers.patch"
