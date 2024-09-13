set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" 83fce0a3f9ef22c90a980b03bb90cbd364d5c9ab
git -C "$PROJECT/repo" apply ../fix_schema_harness.patch
