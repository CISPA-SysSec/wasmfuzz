set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" 13a3df99ffe2521a903f270abb33aa7092b34147
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" ca1e27dd6a194b0d9524cc6842cc120cf1ebd26d
git -C "$PROJECT/libxml2" apply ../libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
