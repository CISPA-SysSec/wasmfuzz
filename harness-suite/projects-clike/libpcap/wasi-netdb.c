/* Name-service stubs for wasm32-wasip1, see wasi-include/netdb.h. */
#include <stddef.h>
#include <netdb.h>

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res)
{
	(void)node; (void)service; (void)hints;
	*res = NULL;
	return EAI_NONAME;
}
void freeaddrinfo(struct addrinfo *ai) { (void)ai; }
const char *gai_strerror(int err) { (void)err; return "name resolution unavailable on WASI"; }
int getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host,
                socklen_t hostlen, char *serv, socklen_t servlen, int flags)
{
	(void)sa; (void)salen; (void)host; (void)hostlen;
	(void)serv; (void)servlen; (void)flags;
	return EAI_FAIL;
}
struct hostent *gethostbyname(const char *name) { (void)name; return NULL; }
struct netent *getnetbyname(const char *name) { (void)name; return NULL; }
struct protoent *getprotobyname(const char *name) { (void)name; return NULL; }
struct servent *getservbyname(const char *name, const char *proto) { (void)name; (void)proto; return NULL; }
