set -e

# libsrtp: upstream HEAD (3.x API, library + fuzzer/ from the same tree).
# Chromium ships 2.8.0 via its mirror (third_party/libsrtp, chromium/deps/libsrtp.git) and Firefox ships 2.8.0;
# upstream fuzzer/ at HEAD only compiles against the 3.x library, so the 2.x mirror is not used.
git clone-rev.sh https://github.com/cisco/libsrtp.git "$PROJECT/libsrtp" 32a3a3a59ffcb2cb92cdc4cd187ac9d944c280de
# Crypto backend: BoringSSL HEAD, as Chromium builds libsrtp against BoringSSL (libsrtp_build_boringssl = true).
git clone-rev.sh https://boringssl.googlesource.com/boringssl "$PROJECT/boringssl" 8eb25be6fa18d475291122887a7bccd3762ff236

git -C "$PROJECT/libsrtp" apply ../port-fuzzer-no-mmap.patch
