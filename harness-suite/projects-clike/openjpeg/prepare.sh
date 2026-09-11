set -e
git clone-rev.sh https://github.com/uclouvain/openjpeg "$PROJECT/repo" 8314119b067c0fc77834731168daaebd379fdb12
git -C "$PROJECT/repo" apply ../port-stub-clocks.patch
git -C "$PROJECT/repo" apply ../fix-pi-decode-alloc.patch
git -C "$PROJECT/repo" apply ../fix-stream-byte-left.patch
