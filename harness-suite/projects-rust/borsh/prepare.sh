set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" 31ecdaf9b0ebd9592239458ffc642996aa3df5be
git -C "$PROJECT/repo" apply "$PROJECT/port-cargo-fuzz.patch"
