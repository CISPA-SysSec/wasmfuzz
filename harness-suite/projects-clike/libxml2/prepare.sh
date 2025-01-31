set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" a8d8a70c510a79a9850e536edc6838b244acb2ef
git -C "$PROJECT/repo" apply ../fix-schema-harness.patch
git -C "$PROJECT/repo" apply ../stub-dup.patch
