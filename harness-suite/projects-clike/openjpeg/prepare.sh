set -e
git clone-rev.sh https://github.com/uclouvain/openjpeg "$PROJECT/repo" 9dd4b3c98a78f50a48fb08f27bf198d4ae1d8528
git -C "$PROJECT/repo" apply ../stub_clocks.patch
git -C "$PROJECT/repo" apply ../fix-pi-decode-alloc.patch
git -C "$PROJECT/repo" apply ../fix-stream-byte-left.patch
