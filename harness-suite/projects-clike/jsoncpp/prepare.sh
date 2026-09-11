set -e
git clone-rev.sh https://github.com/open-source-parsers/jsoncpp.git  "$PROJECT/repo" 3347a4b86bb914cb565f0cbda19c06e109513300
git -C "$PROJECT/repo" apply ../port-wasi-exceptions.patch
