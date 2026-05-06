set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" b15a388a6148e1a61c52f2c057b4554db08ce808
git -C "$PROJECT/repo" apply ../stub-dup.patch
