set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" fe778bec428d5b44cd4922c896af0a7c39a863dd
git -C "$PROJECT/repo" apply "$PROJECT/port-cargo-fuzz.patch"
