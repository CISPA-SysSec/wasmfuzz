set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" a8d8a70c510a79a9850e536edc6838b244acb2ef
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 65196fdd1a385f22114f245a9002ee8dc899f2c4
git -C "$PROJECT/libxml2" apply ../libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
