set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" c63248941708bc1d2e3a4292954593312212f6ca
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 7b0ecd5af8689a0bc5df358cd6289aab0f266183
git -C "$PROJECT/libxml2" apply ../port-libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../port-libarchive-stubs.patch
