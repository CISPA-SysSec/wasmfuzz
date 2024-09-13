set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" f16cd07e3c982539352aa43f65abf3607461a7bc
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
