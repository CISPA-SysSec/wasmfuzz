set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" a577f35bd5bb84beb7d3b7ba36081b88fdde4a5d
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
