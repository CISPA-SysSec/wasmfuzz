set -e
# libxml2 and libxslt at upstream HEAD; Chromium ships libxslt 35323d6a15 and libxml2 81c05bafd4
# (third_party/{libxslt,libxml}/README.chromium).
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" c43dc98d27ac315a48d93dbd399c6c22cf7125b1
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxslt.git "$PROJECT/libxslt" ec95343e75c503523b91495f021d109173e169c4
# Chromium's downstream modifications (diff of chromium/src/third_party/{libxml,libxslt}/src
# against Chromium's upstream pins; see chromium/*.patch + roll.py there).
git -C "$PROJECT/libxml2" apply ../chromium-libxml2.patch
git -C "$PROJECT/libxslt" apply ../chromium-libxslt.patch
git -C "$PROJECT/libxml2" apply ../port-libxml2-stub-dup.patch
