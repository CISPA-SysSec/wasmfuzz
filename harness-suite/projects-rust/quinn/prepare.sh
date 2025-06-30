set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" e8dc5a2eda57163bfbaba52ba57bf5b7a0027e22
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
