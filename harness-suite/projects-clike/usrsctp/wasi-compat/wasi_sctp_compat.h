/* Force-included compatibility shim for building usrsctp (AF_CONN only,
 * no kernel sockets) for wasm32-wasip1. wasi-libc's socket headers are
 * minimal; supply the few BSD socket definitions usrsctp needs at compile
 * time. None of these reach a real OS socket in the AF_CONN-only build. */
#ifndef WASI_SCTP_COMPAT_H
#define WASI_SCTP_COMPAT_H
#if defined(__wasi__)
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

/* wasi-libc (wasm32-wasip1, single-threaded) never initializes the main
 * thread's robust_list, so locking a PTHREAD_MUTEX_ERRORCHECK (or RECURSIVE)
 * mutex dereferences a NULL list head and traps. usrsctp only asks for
 * ERRORCHECK as a debugging aid; its lock asserts use trylock()==EBUSY,
 * which works the same for NORMAL mutexes. */
#undef PTHREAD_MUTEX_ERRORCHECK
#define PTHREAD_MUTEX_ERRORCHECK PTHREAD_MUTEX_NORMAL

#ifndef MSG_OOB
#define MSG_OOB       0x0001
#endif
#ifndef MSG_DONTROUTE
#define MSG_DONTROUTE 0x0004
#endif
#ifndef MSG_CTRUNC
#define MSG_CTRUNC    0x0008
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT  0x0040
#endif
#ifndef MSG_EOR
#define MSG_EOR       0x0080
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL  0x4000
#endif
#ifndef SOCK_RAW
#define SOCK_RAW       3
#endif
#ifndef SOCK_SEQPACKET
#define SOCK_SEQPACKET 5
#endif
#ifndef SOMAXCONN
#define SOMAXCONN 128
#endif
#ifndef SO_ERROR
#define SO_ERROR 4
#endif
#ifndef SO_SNDBUF
#define SO_SNDBUF 7
#endif
#ifndef SO_RCVBUF
#define SO_RCVBUF 8
#endif
#ifndef SO_LINGER
#define SO_LINGER 13
#endif
#ifndef SO_ACCEPTCONN
#define SO_ACCEPTCONN 30
#endif
#ifndef ERESTART
#define ERESTART 85
#endif

#ifndef CMSG_ALIGN
struct cmsghdr {
	socklen_t cmsg_len;
	int cmsg_level;
	int cmsg_type;
};
#define CMSG_ALIGN(len) (((len) + sizeof(size_t) - 1) & (size_t) ~(sizeof(size_t) - 1))
#define CMSG_DATA(cmsg) ((unsigned char *) (((struct cmsghdr *)(cmsg)) + 1))
#define CMSG_SPACE(len) (CMSG_ALIGN(len) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_LEN(len)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif

/* not provided by wasi-libc; same as usrsctp's own fallback */
static inline int
timingsafe_bcmp(const void *b1, const void *b2, size_t n)
{
	const unsigned char *p1 = b1, *p2 = b2;
	int ret = 0;

	for (; n > 0; n--)
		ret |= *p1++ ^ *p2++;
	return (ret != 0);
}
#endif /* __wasi__ */
#endif
