set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" ddcb79dc9934fd8a26263f6368c4eb7aa43f6d49
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" f5509ae993ac30417f81acc5118f232ae3f2d27d
git -C "$PROJECT/libxml2" apply ../libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
