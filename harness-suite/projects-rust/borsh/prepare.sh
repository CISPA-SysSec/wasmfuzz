set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" a34f32481138bfbf1998a36189471e61ee3fe056
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
