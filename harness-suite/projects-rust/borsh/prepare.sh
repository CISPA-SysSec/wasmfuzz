set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" f1b75a6b50740bfb6231b7d0b1bd93ea58ca5452
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
