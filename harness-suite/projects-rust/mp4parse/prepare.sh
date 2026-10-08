set -e
# upstream HEAD; Firefox vendors mp4parse 0.17.0 by git rev (firefox/Cargo.lock).
git clone-rev.sh https://github.com/mozilla/mp4parse-rust.git "$PROJECT/repo" 95d98b9a6840f5bfc9a2323b3fa3f56d7f3c6077
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-firefox-api-usage.patch"
