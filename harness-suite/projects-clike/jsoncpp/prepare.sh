set -e
git clone-rev.sh https://github.com/open-source-parsers/jsoncpp.git  "$PROJECT/repo" 755d0a69d7109d465db6196a3c7e1c6f3c62a48f
git -C "$PROJECT/repo" apply ../patch_eh.patch
