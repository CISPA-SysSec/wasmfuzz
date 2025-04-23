set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" 1039cd53bc5761f1eb30afc3510f92a57d88ce5a
git -C "$PROJECT/repo" apply ../stub-dup.patch
