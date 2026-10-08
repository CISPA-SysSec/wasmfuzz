set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" c43dc98d27ac315a48d93dbd399c6c22cf7125b1
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" caacb791cc9487eacc2a8826875871a77f57bdf0
git -C "$PROJECT/libxml2" apply ../port-libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../port-libarchive-stubs.patch
