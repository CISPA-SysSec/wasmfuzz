set -e
# upstream HEAD; Chromium vendors serde_json 1.0.151, Firefox 1.0.149.
git clone-rev.sh https://github.com/serde-rs/json "$PROJECT/repo" afdf6fc67247dd7fa4fcde1381e6ecc6bcc7a30e
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-browser-features-roundtrip.patch"
