set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" ee0eda4b12ae476905c4a265dc9a190ad76bc7b2
git -C "$PROJECT/repo" apply ../stub-dup.patch
