set -e
git clone-rev.sh https://github.com/uclouvain/openjpeg "$PROJECT/repo" 362ec6c92dbc0f563810fafe552e4fa0d9fde024
git -C "$PROJECT/repo" apply ../stub_clocks.patch
