set -e
git clone-rev.sh https://github.com/Byron/gitoxide.git "$PROJECT/repo" 5fb3dcf6a86ac0c403776c8820bf5d23f187f7e1
git -C "$PROJECT/repo" apply "$PROJECT/port-disable-incompatible-fuzz.patch"
git -C "$PROJECT/repo" apply "$PROJECT/port-wasi-path-convert.patch"
