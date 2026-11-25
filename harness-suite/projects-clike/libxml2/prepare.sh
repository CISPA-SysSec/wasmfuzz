set -e
git clone-rev.sh https://gitlab.gnome.org/GNOME/libxml2.git "$PROJECT/repo" 21c8223ac091b81d5914c52eb20b1b063e29cb92
git -C "$PROJECT/repo" apply ../port-libxml2-stub-dup.patch
git -C "$PROJECT/repo" apply ../fix-schemas-circular-list-type.patch
git -C "$PROJECT/repo" apply ../fix-schemas-canon-value-double-free.patch
git -C "$PROJECT/repo" apply ../fix-push-pi-in-internal-subset.patch
git -C "$PROJECT/repo" apply ../fix-copy-entity-children-oom.patch
git -C "$PROJECT/repo" apply ../fix-parse-external-id-grow.patch
git -C "$PROJECT/repo" apply ../fix-schemas-pending-items-realloc.patch
git -C "$PROJECT/repo" apply ../fix-schemas-attr-group-expand-failure.patch
git -C "$PROJECT/repo" apply ../fix-parse-element-decl-grow.patch
git -C "$PROJECT/repo" apply ../fix-valid-notation-attr-oom.patch
git -C "$PROJECT/repo" apply ../fix-push-utf16-crlf-split.patch
