set -e

# libsrtp: upstream HEAD (3.x API, library + fuzzer/ from the same tree).
# Chromium ships 2.8.0 via its mirror (third_party/libsrtp, chromium/deps/libsrtp.git) and Firefox ships 2.8.0;
# upstream fuzzer/ at HEAD only compiles against the 3.x library, so the 2.x mirror is not used.
git clone-rev.sh https://github.com/cisco/libsrtp.git "$PROJECT/libsrtp" 052aa2965e2c26f737087492d37a31c3ee09ddba
# Crypto backend: BoringSSL HEAD, as Chromium builds libsrtp against BoringSSL (libsrtp_build_boringssl = true).
git clone-rev.sh https://boringssl.googlesource.com/boringssl "$PROJECT/boringssl" 39952e30dd65e8cda4dc70d239a62af442872b6e

git -C "$PROJECT/libsrtp" apply ../port-fuzzer-no-mmap.patch
# b83ecd1 (-Wshorten-64-to-32) added INT_MAX checks that rely on OpenSSL including <limits.h>; BoringSSL does not
git -C "$PROJECT/libsrtp" apply ../fix-ossl-include-limits-h.patch
