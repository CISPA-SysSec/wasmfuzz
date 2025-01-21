set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" 72f84dd739792b791e8c6efd670c389c1f5dc8c1
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 819a50a0436531276e388fc97eb0b1b61d2134a3
git -C "$PROJECT/libxml2" apply ../libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
