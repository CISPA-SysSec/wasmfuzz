set -e
git clone-rev.sh https://github.com/near/borsh-rs.git "$PROJECT/repo" 0dc09cd4d5cf7a95686d044222557df106a62e1c
git -C "$PROJECT/repo" apply "$PROJECT/0001-cargo-fuzz.patch"
