set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" 0f9432f7c1cab0ea1469d02a935a89dae28693b7
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
