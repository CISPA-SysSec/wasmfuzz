set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" 513949293d7ee2a11acc36bcdf5016a8fc5cc438
git -C "$PROJECT/repo" apply ../fix-schema-harness.patch
git -C "$PROJECT/repo" apply ../stub-dup.patch
