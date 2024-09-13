set -e
git clone-rev.sh https://github.com/uclouvain/openjpeg "$PROJECT/repo" 606304d08365469d0fd685f2312791fc0feac15f
git -C "$PROJECT/repo" apply ../stub_clocks.patch
