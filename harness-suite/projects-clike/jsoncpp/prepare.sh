set -e
git clone-rev.sh https://github.com/open-source-parsers/jsoncpp.git  "$PROJECT/repo" edc01ab10f52135ec80e3589b6b4e0a9c65b27fd
git -C "$PROJECT/repo" apply ../patch_eh.patch
