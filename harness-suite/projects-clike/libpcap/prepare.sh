set -e
apt-get update && apt-get install -y flex bison
git clone-rev.sh https://github.com/the-tcpdump-group/libpcap.git "$PROJECT/repo" e7323b83f1ff04e6100d293f9a3e640b9af48b06
git -C "$PROJECT/repo" apply ../port-wasi-no-lookupnet.patch
git -C "$PROJECT/repo" apply ../port-fuzz-both-memfile.patch
