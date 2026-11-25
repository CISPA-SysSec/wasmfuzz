#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Library configuration mirrors Firefox's netwerk/sctp/src/moz.build
# (AF_CONN only: no INET/INET6, so no raw/UDP sockets and no recv threads),
# plus INVARIANTS as in oss-fuzz (-Dsctp_invariants=1).
DEFS="-D__Userspace__ -DSCTP_SIMPLE_ALLOCATOR -DSCTP_PROCESS_LEVEL_LOCKS -DSCTP_DEBUG -DINVARIANTS -D_GNU_SOURCE"

case $BUILD_TYPE in
    wasi-*)
        COMPAT="-I$PROJECT/wasi-compat -include wasi_sctp_compat.h"
        ;;
    *)
        COMPAT=""
        ;;
esac

SRCS="netinet/sctp_asconf.c netinet/sctp_auth.c netinet/sctp_bsd_addr.c netinet/sctp_callout.c
      netinet/sctp_cc_functions.c netinet/sctp_crc32.c netinet/sctp_indata.c netinet/sctp_input.c
      netinet/sctp_output.c netinet/sctp_pcb.c netinet/sctp_peeloff.c netinet/sctp_sha1.c
      netinet/sctp_ss_functions.c netinet/sctp_sysctl.c netinet/sctp_timer.c netinet/sctp_userspace.c
      netinet/sctp_usrreq.c netinet/sctputil.c netinet6/sctp6_usrreq.c
      user_environment.c user_mbuf.c user_recv_thread.c user_socket.c"

mkdir -p build
(
    cd usrsctplib
    for src in $SRCS; do
        obj="../build/$(echo "$src" | tr '/' '_' | sed 's/\.c$/.o/')"
        $CC $CFLAGS $DEFS $COMPAT -I. -w -c "$src" -o "$obj" &
    done
    wait
)
llvm-ar rcs build/libusrsctp.a build/*.o 2>/dev/null || ar rcs build/libusrsctp.a build/*.o

# oss-fuzz/projects/usrsctp/build.sh: fuzzer_connect fuzzer_listen fuzzer_fragment, FUZZING_STAGE=0
cd fuzzer
for target in connect listen fragment; do
    $CC $CFLAGS -DFUZZING_STAGE=0 -D_GNU_SOURCE $COMPAT -I. -I../usrsctplib \
        fuzzer_$target.c ../programs/programs_helper.c ../build/libusrsctp.a \
        $LIB_FUZZING_ENGINE \
        -o /out/usrsctp-$target.wasm
done
