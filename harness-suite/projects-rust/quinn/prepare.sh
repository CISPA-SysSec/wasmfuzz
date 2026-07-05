set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" fed0321a9a672819662caab37f5662f1ad91308e
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
