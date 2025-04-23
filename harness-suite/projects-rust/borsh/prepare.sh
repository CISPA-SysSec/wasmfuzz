set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" abb9582c70b2afd54eef302c23b6e6d3a0b2c1c4
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
