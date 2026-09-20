set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" 91586dc6742ab335682235120363f6e126eea5e2
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" abaa707d92fce052f386b6cc2c8d0593ce61e639
git -C "$PROJECT/libxml2" apply ../port-libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../port-libarchive-stubs.patch
