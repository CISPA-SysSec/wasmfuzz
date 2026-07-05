#ifndef POPPLER_WASI_ICONV_H
#define POPPLER_WASI_ICONV_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *iconv_t;

#define ICONV_CONST

iconv_t iconv_open(const char *tocode, const char *fromcode);
size_t iconv(iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
int iconv_close(iconv_t cd);

#ifdef __cplusplus
}
#endif

#endif
