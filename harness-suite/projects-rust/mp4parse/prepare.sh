set -e
# upstream HEAD; Firefox vendors mp4parse 0.17.0 by git rev (firefox/Cargo.lock).
git clone-rev.sh https://github.com/mozilla/mp4parse-rust.git "$PROJECT/repo" d3a9abfc93b22687e5e5cd9df86697adcb7d5887
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-firefox-api-usage.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-untrusted-preallocation.patch"
