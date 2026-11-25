set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/libxml2" 21c8223ac091b81d5914c52eb20b1b063e29cb92
git clone-rev.sh https://github.com/libarchive/libarchive.git "$PROJECT/libarchive" c6a3eaa4c4aecc3b58795ec58899ea0b1366a45f
git -C "$PROJECT/libxml2" apply ../port-libxml2-stub-dup.patch
git -C "$PROJECT/libarchive" apply ../port-libarchive-stubs.patch
git -C "$PROJECT/libarchive" apply ../fix-stale-errno-in-string-conversion.patch
git -C "$PROJECT/libarchive" apply ../fix-iso9660-directory-size-overflow.patch
git -C "$PROJECT/libarchive" apply ../fix-tar-nodata-entry-disk-size.patch
