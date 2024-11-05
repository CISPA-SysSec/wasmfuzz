set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" b416d111b9380a76f23c42b83b06266b332fbf50
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
