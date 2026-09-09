set -e
git clone-rev.sh https://gitlab.xiph.org/xiph/ogg.git "$PROJECT/repo/ogg" 06a5e0262cdc28aa4ae6797627a783b5010440f0
git clone-rev.sh https://gitlab.xiph.org/xiph/vorbis.git "$PROJECT/repo" 1b75110b5a2754ba1931d82dd83cb822b266a21d
git -C "$PROJECT/repo" apply "$PROJECT/fix-decodevs-add-zero-dim.patch"
