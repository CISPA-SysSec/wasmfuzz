set -e
# libxml2 and libxslt at upstream HEAD; Chromium ships libxslt 35323d6a15 and libxml2 81c05bafd4
# (third_party/{libxslt,libxml}/README.chromium).
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" 21c8223ac091b81d5914c52eb20b1b063e29cb92
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxslt.git "$PROJECT/libxslt" 24ee4028314847b061c2a2a50919b36736828bea
# Chromium's downstream modifications (diff of chromium/src/third_party/{libxml,libxslt}/src
# against Chromium's upstream pins; see chromium/*.patch + roll.py there).
git -C "$PROJECT/libxml2" apply ../chromium-libxml2.patch
git -C "$PROJECT/libxslt" apply ../chromium-libxslt.patch
git -C "$PROJECT/libxml2" apply ../port-libxml2-stub-dup.patch
