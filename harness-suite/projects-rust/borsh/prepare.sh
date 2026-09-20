set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" c9a2ed48927612db0d1329d54a12ced2035b4f20
git -C "$PROJECT/repo" apply "$PROJECT/port-cargo-fuzz.patch"
