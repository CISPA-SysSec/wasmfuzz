set -e
# upstream HEAD; Chromium vendors moxcms 0.8.1 (third_party/rust/chromium_crates_io).
git clone-rev.sh https://github.com/awxkee/moxcms "$PROJECT/repo" fc1b029b04f84e11937ff59de3fba35a6034a8df
git -C "$PROJECT/repo" apply "$PROJECT/port-drop-app-workspace-member.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-drop-lut-target.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-chromium-icc-to-srgb.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-trc-tag-offset-overflow.patch"
