set -e
git clone-rev.sh https://github.com/uclouvain/openjpeg "$PROJECT/repo" 44119c2db51911056e1227e46a0ea883e3d73fbf
git -C "$PROJECT/repo" apply ../stub_clocks.patch
