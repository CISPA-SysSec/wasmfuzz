set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" c43dc98d27ac315a48d93dbd399c6c22cf7125b1
git -C "$PROJECT/repo" apply ../port-libxml2-stub-dup.patch
