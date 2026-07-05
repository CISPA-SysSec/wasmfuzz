set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" 3348776d27adf4df8acd0694238590d25e485258
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
