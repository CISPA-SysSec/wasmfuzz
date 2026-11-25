set -e
# upstream HEAD (dev branch); Chromium ships 10da6ba6de (third_party/zstd), Firefox v1.5.7-kernel.
git clone-rev.sh https://github.com/facebook/zstd.git "$PROJECT/repo" 8f09f939258348ddd4ecac86da4536a1ce007eb8
git -C "$PROJECT/repo" apply ../fuzz-sequence-compression-api-dict-size.patch
