set -e
git clone-rev.sh https://github.com/uclouvain/openjpeg "$PROJECT/repo" 21b70b0d62807e270994f94302e323da4f0d776b
git -C "$PROJECT/repo" apply ../stub_clocks.patch
git -C "$PROJECT/repo" apply ../fix-pi-decode-alloc.patch
