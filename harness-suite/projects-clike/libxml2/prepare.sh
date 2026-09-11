set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" c63248941708bc1d2e3a4292954593312212f6ca
git -C "$PROJECT/repo" apply ../port-libxml2-stub-dup.patch
