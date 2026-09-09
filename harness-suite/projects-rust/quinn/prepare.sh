set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" 65a87d40c22e0818e50adfa277611610d792a43d
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
