set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" 83fce0a3f9ef22c90a980b03bb90cbd364d5c9ab
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 8dbb3b4d54213f988fce77c7fa7eaf63249cdbb5
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
