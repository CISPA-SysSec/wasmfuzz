set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" 169857ad264e51d9b34d7119d2e2e006e35e60c2
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 819a50a0436531276e388fc97eb0b1b61d2134a3
git -C "$PROJECT/libxml2" apply ../libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
