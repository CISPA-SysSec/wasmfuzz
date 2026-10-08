set -e
# upstream HEAD (dev branch); Chromium ships 10da6ba6de (third_party/zstd), Firefox v1.5.7-kernel.
git clone-rev.sh https://github.com/facebook/zstd.git "$PROJECT/repo" 01b7154f1172432f8abe9b3bb9909e14a1176b7d
git -C "$PROJECT/repo" apply ../fuzz-sequence-compression-api-dict-size.patch
