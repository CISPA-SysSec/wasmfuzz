set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" 513949293d7ee2a11acc36bcdf5016a8fc5cc438
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 40ff837717b89e9a5d2c735758f503d124d17b72
git -C "$PROJECT/libxml2" apply ../libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
