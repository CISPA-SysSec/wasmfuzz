set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" b15a388a6148e1a61c52f2c057b4554db08ce808
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" 4b65c3866bc97c72897f00c7b7bb5c993a6de5a4
git -C "$PROJECT/libxml2" apply ../libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
git -C "$PROJECT/libarchive" apply ../fixes.patch
