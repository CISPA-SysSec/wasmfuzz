set -e
git clone-rev.sh https://gitlab.xiph.org/xiph/ogg.git "$PROJECT/repo/ogg" 06a5e0262cdc28aa4ae6797627a783b5010440f0
git clone-rev.sh https://gitlab.xiph.org/xiph/vorbis.git "$PROJECT/repo" e3c9861ff096d52378e131ff8c334552e09cdffa
git -C "$PROJECT/repo" apply "$PROJECT/fix-decodevs-add-zero-dim.patch"
