set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" a1931ab8c37e09d915ad1dcb846624ccd72e04a9
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
