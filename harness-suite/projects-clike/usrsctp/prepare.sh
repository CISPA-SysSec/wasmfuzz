set -e

# upstream HEAD; Firefox ships 1330843b6f (netwerk/sctp/src/moz.yaml). Chromium no longer
# ships usrsctp (it uses dcsctp).
git clone-rev.sh https://github.com/sctplab/usrsctp.git "$PROJECT/repo" c8aebc95f877c7d506942d84b40e3ae6e5cfc9c7

# Firefox's downstream patches (netwerk/sctp/src/*.patch;
# paths are relative to usrsctplib/ as Firefox flattens that directory).
for p in tsn-gap-check flush-before-process-init interleaving-supported-define; do
    git -C "$PROJECT/repo" apply --directory=usrsctplib "../fix-firefox-$p.patch"
done

git -C "$PROJECT/repo" apply ../port-fuzzer-init-nothreads.patch
git -C "$PROJECT/repo" apply ../fuzz-fragment-assoc-vtag.patch
git -C "$PROJECT/repo" apply ../fix-tsn-compare-macro-parens.patch
git -C "$PROJECT/repo" apply ../fix-process-init-stale-mapping-arrays.patch
git -C "$PROJECT/repo" apply ../fix-pktdrop-cwnd-div-zero.patch
