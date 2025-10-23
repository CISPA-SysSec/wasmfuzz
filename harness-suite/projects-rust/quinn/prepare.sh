set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" 531ca90ec9f8fc2f8cba05564bc8d3a439884975
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
