set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" db60822629ee00078e6c9b0105b2ef9d2ccc72f6
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
