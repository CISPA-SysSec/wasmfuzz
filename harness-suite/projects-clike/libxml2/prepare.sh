set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" 13a3df99ffe2521a903f270abb33aa7092b34147
git -C "$PROJECT/repo" apply ../stub-dup.patch
