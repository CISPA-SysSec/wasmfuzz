set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" 7fc21fe52d39b3d3c7409b6ab272976a21b5f482
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
