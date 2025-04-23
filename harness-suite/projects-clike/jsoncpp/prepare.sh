set -e
git clone-rev.sh https://github.com/open-source-parsers/jsoncpp.git  "$PROJECT/repo" ca98c98457b1163cca1f7d8db62827c115fec6d1
git -C "$PROJECT/repo" apply ../patch_eh.patch
