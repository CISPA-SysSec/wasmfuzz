set -e
# upstream HEAD; Chromium vendors serde_json 1.0.151, Firefox 1.0.149.
git clone-rev.sh https://github.com/serde-rs/json "$PROJECT/repo" f51fa15a7015c7d02817a46d2db44c899a0016e8
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-browser-features-roundtrip.patch"
