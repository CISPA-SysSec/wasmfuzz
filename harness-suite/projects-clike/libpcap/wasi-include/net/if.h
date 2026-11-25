/* wasm32-wasip1 has no <net/if.h>; libpcap's offline (PCAP_TYPE=null) build
 * only needs it to exist plus IFNAMSIZ/IF_NAMESIZE. */
#ifndef WASMFUZZ_NET_IF_SHIM_H
#define WASMFUZZ_NET_IF_SHIM_H
#define IFNAMSIZ 16
#define IF_NAMESIZE IFNAMSIZ
#endif
