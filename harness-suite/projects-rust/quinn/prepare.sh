set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" 6b901a3c278f58497d6d53c64ef1cc53497c625b
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
