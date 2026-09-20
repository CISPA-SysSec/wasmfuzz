set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" 91586dc6742ab335682235120363f6e126eea5e2
git -C "$PROJECT/repo" apply ../port-libxml2-stub-dup.patch
