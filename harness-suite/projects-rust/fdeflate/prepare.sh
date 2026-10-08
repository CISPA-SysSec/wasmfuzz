set -e
# upstream HEAD; Chromium vendors fdeflate 0.3.7 (third_party/rust/chromium_crates_io).
git clone-rev.sh https://github.com/image-rs/fdeflate "$PROJECT/repo" a713d02c560526c82e2b97519ed6720bdbc8a47a
