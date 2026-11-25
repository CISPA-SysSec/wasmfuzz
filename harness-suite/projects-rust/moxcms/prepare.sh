set -e
# upstream HEAD; Chromium vendors moxcms 0.8.1 (third_party/rust/chromium_crates_io).
git clone-rev.sh https://github.com/awxkee/moxcms "$PROJECT/repo" bf407608004ad3b1aabef68d824e353e3989db04
git -C "$PROJECT/repo" apply "$PROJECT/port-drop-app-workspace-member.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-drop-lut-target.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-chromium-icc-to-srgb.patch"
