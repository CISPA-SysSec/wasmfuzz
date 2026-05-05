set -e
git clone-rev.sh https://github.com/quinn-rs/quinn/ "$PROJECT/repo" c9b40f1096a3301d699a0118359f5b176dde38d1
# TODO: `cargo update -p arbitrary@1.4.1` would also work. Is there a better solution?
rm "$PROJECT/repo/Cargo.lock"
