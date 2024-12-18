set -e
git clone-rev.sh https://github.com/uclouvain/openjpeg "$PROJECT/repo" eb25a5ec777ff6699f4bb1187740467dcfa64dd6
git -C "$PROJECT/repo" apply ../stub_clocks.patch
