set -e
git clone-rev.sh https://github.com/open-source-parsers/jsoncpp.git  "$PROJECT/repo" 93acc7b155048f1a66c43235cc205519f1e7a6ea
git -C "$PROJECT/repo" apply ../port-wasi-exceptions.patch
