set -e
git clone-rev.sh https://github.com/ruuda/claxon.git "$PROJECT/repo" 890338d08cbf02f70767fa01580603b91828261d
git -C "$PROJECT/repo" apply "$PROJECT/0001-update-fuzzers.patch"
