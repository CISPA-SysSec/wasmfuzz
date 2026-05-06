set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" f8109c75dd9462a2bc756c9d6fe3c0bc9c3e24ac
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
