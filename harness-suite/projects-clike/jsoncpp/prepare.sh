set -e
git clone-rev.sh https://github.com/open-source-parsers/jsoncpp.git  "$PROJECT/repo" 800aa28c493590c539cb7baf445016cc9b8702ef
git -C "$PROJECT/repo" apply ../patch_eh.patch
