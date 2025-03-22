set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" ee0eda4b12ae476905c4a265dc9a190ad76bc7b2
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" a323e5fa6811e77e1bf6b7fad7deaa8c2281d900
git -C "$PROJECT/libxml2" apply ../libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../libarchive_stubs.patch
