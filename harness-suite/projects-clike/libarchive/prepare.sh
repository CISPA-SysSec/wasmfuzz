set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" 1039cd53bc5761f1eb30afc3510f92a57d88ce5a
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" de73860cda5a49f97289a9924a3c5590edafef66
git -C "$PROJECT/libxml2" apply ../libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
