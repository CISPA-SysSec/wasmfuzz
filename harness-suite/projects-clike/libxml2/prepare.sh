set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" a3992815b3d4caa4a6709406ca085c9f93856809
git -C "$PROJECT/repo" apply ../stub-dup.patch
