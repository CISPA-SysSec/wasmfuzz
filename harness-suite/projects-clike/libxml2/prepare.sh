set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" ddcb79dc9934fd8a26263f6368c4eb7aa43f6d49
git -C "$PROJECT/repo" apply ../stub-dup.patch
