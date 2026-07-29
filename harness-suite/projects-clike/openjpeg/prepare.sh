set -e
git clone-rev.sh https://github.com/uclouvain/openjpeg "$PROJECT/repo" 402ef5862195b177ea0a7788f2a6ef2804e62285
git -C "$PROJECT/repo" apply ../stub_clocks.patch
git -C "$PROJECT/repo" apply ../fix-pi-decode-alloc.patch
git -C "$PROJECT/repo" apply ../fix-stream-byte-left.patch
