#include "wasi-iconv.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum wasi_iconv_mode {
    WASI_ICONV_UTF8_TO_UTF16LE,
    WASI_ICONV_UTF16LE_TO_UTF8,
    WASI_ICONV_UTF8_TO_UTF16BE,
    WASI_ICONV_UTF16BE_TO_UTF8,
};

struct wasi_iconv_desc {
    enum wasi_iconv_mode mode;
};

static int encoding_pair(const char *to, const char *from, enum wasi_iconv_mode *mode)
{
    if (!strcmp(to, "UTF-8") && !strcmp(from, "UTF-16LE")) {
        *mode = WASI_ICONV_UTF16LE_TO_UTF8;
        return 0;
    }
    if (!strcmp(to, "UTF-16LE") && !strcmp(from, "UTF-8")) {
        *mode = WASI_ICONV_UTF8_TO_UTF16LE;
        return 0;
    }
    if (!strcmp(to, "UTF-8") && !strcmp(from, "UTF-16BE")) {
        *mode = WASI_ICONV_UTF16BE_TO_UTF8;
        return 0;
    }
    if (!strcmp(to, "UTF-16BE") && !strcmp(from, "UTF-8")) {
        *mode = WASI_ICONV_UTF8_TO_UTF16BE;
        return 0;
    }
    return -1;
}

iconv_t iconv_open(const char *tocode, const char *fromcode)
{
    struct wasi_iconv_desc *desc = calloc(1, sizeof(*desc));
    if (!desc) {
        return (iconv_t)-1;
    }
    if (encoding_pair(tocode, fromcode, &desc->mode) != 0) {
        free(desc);
        errno = EINVAL;
        return (iconv_t)-1;
    }
    return (iconv_t)desc;
}

static size_t utf8_to_utf16(const uint8_t *in, size_t in_len, uint16_t *out, size_t out_units)
{
    size_t in_pos = 0;
    size_t out_pos = 0;
    while (in_pos < in_len) {
        uint32_t cp;
        uint8_t b0 = in[in_pos++];
        if (b0 < 0x80) {
            cp = b0;
        } else if ((b0 & 0xE0) == 0xC0) {
            if (in_pos >= in_len) {
                return (size_t)-1;
            }
            cp = ((uint32_t)(b0 & 0x1F) << 6) | (in[in_pos++] & 0x3F);
        } else if ((b0 & 0xF0) == 0xE0) {
            if (in_pos + 1 > in_len) {
                return (size_t)-1;
            }
            cp = ((uint32_t)(b0 & 0x0F) << 12) | ((uint32_t)(in[in_pos++] & 0x3F) << 6) | (in[in_pos++] & 0x3F);
        } else if ((b0 & 0xF8) == 0xF0) {
            if (in_pos + 2 > in_len) {
                return (size_t)-1;
            }
            cp = ((uint32_t)(b0 & 0x07) << 18) | ((uint32_t)(in[in_pos++] & 0x3F) << 12) | ((uint32_t)(in[in_pos++] & 0x3F) << 6) | (in[in_pos++] & 0x3F);
        } else {
            return (size_t)-1;
        }
        if (cp <= 0xFFFF) {
            if (out_pos + 1 > out_units) {
                return (size_t)-1;
            }
            out[out_pos++] = (uint16_t)cp;
        } else {
            if (out_pos + 2 > out_units) {
                return (size_t)-1;
            }
            cp -= 0x10000;
            out[out_pos++] = (uint16_t)(0xD800 + (cp >> 10));
            out[out_pos++] = (uint16_t)(0xDC00 + (cp & 0x3FF));
        }
    }
    return out_pos;
}

static size_t utf16le_to_utf8(const uint16_t *in, size_t in_units, uint8_t *out, size_t out_len)
{
    size_t in_pos = 0;
    size_t out_pos = 0;
    while (in_pos < in_units) {
        uint32_t cp = in[in_pos++];
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (in_pos >= in_units) {
                return (size_t)-1;
            }
            uint32_t low = in[in_pos++];
            if (low < 0xDC00 || low > 0xDFFF) {
                return (size_t)-1;
            }
            cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
        }
        if (cp < 0x80) {
            if (out_pos + 1 > out_len) {
                return (size_t)-1;
            }
            out[out_pos++] = (uint8_t)cp;
        } else if (cp < 0x800) {
            if (out_pos + 2 > out_len) {
                return (size_t)-1;
            }
            out[out_pos++] = (uint8_t)(0xC0 | (cp >> 6));
            out[out_pos++] = (uint8_t)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            if (out_pos + 3 > out_len) {
                return (size_t)-1;
            }
            out[out_pos++] = (uint8_t)(0xE0 | (cp >> 12));
            out[out_pos++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            out[out_pos++] = (uint8_t)(0x80 | (cp & 0x3F));
        } else {
            if (out_pos + 4 > out_len) {
                return (size_t)-1;
            }
            out[out_pos++] = (uint8_t)(0xF0 | (cp >> 18));
            out[out_pos++] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
            out[out_pos++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            out[out_pos++] = (uint8_t)(0x80 | (cp & 0x3F));
        }
    }
    return out_pos;
}

static size_t utf16be_to_utf8(const uint16_t *in, size_t in_units, uint8_t *out, size_t out_len)
{
    size_t in_pos = 0;
    size_t out_pos = 0;
    while (in_pos < in_units) {
        uint32_t cp = ((uint32_t)in[in_pos] << 8) | (in[in_pos] >> 8);
        in_pos++;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (in_pos >= in_units) {
                return (size_t)-1;
            }
            uint32_t low = ((uint32_t)in[in_pos] << 8) | (in[in_pos] >> 8);
            in_pos++;
            if (low < 0xDC00 || low > 0xDFFF) {
                return (size_t)-1;
            }
            cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
        }
        if (cp < 0x80) {
            if (out_pos + 1 > out_len) {
                return (size_t)-1;
            }
            out[out_pos++] = (uint8_t)cp;
        } else if (cp < 0x800) {
            if (out_pos + 2 > out_len) {
                return (size_t)-1;
            }
            out[out_pos++] = (uint8_t)(0xC0 | (cp >> 6));
            out[out_pos++] = (uint8_t)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            if (out_pos + 3 > out_len) {
                return (size_t)-1;
            }
            out[out_pos++] = (uint8_t)(0xE0 | (cp >> 12));
            out[out_pos++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            out[out_pos++] = (uint8_t)(0x80 | (cp & 0x3F));
        } else {
            if (out_pos + 4 > out_len) {
                return (size_t)-1;
            }
            out[out_pos++] = (uint8_t)(0xF0 | (cp >> 18));
            out[out_pos++] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
            out[out_pos++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            out[out_pos++] = (uint8_t)(0x80 | (cp & 0x3F));
        }
    }
    return out_pos;
}

size_t iconv(iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
    struct wasi_iconv_desc *desc = (struct wasi_iconv_desc *)cd;
    if (!desc || !inbuf || !inbytesleft || !outbuf || !outbytesleft) {
        errno = EINVAL;
        return (size_t)-1;
    }

    size_t produced = 0;
    switch (desc->mode) {
    case WASI_ICONV_UTF8_TO_UTF16LE: {
        size_t units = *outbytesleft / sizeof(uint16_t);
        produced = utf8_to_utf16((const uint8_t *)*inbuf, *inbytesleft, (uint16_t *)*outbuf, units);
        if (produced == (size_t)-1) {
            errno = E2BIG;
            return (size_t)-1;
        }
        *inbuf += *inbytesleft;
        *inbytesleft = 0;
        *outbuf += produced * sizeof(uint16_t);
        *outbytesleft -= produced * sizeof(uint16_t);
        break;
    }
    case WASI_ICONV_UTF16LE_TO_UTF8: {
        size_t units = *inbytesleft / sizeof(uint16_t);
        produced = utf16le_to_utf8((const uint16_t *)*inbuf, units, (uint8_t *)*outbuf, *outbytesleft);
        if (produced == (size_t)-1) {
            errno = E2BIG;
            return (size_t)-1;
        }
        *inbuf += units * sizeof(uint16_t);
        *inbytesleft -= units * sizeof(uint16_t);
        *outbuf += produced;
        *outbytesleft -= produced;
        break;
    }
    case WASI_ICONV_UTF8_TO_UTF16BE: {
        size_t units = *outbytesleft / sizeof(uint16_t);
        size_t le_produced = utf8_to_utf16((const uint8_t *)*inbuf, *inbytesleft, (uint16_t *)*outbuf, units);
        if (le_produced == (size_t)-1) {
            errno = E2BIG;
            return (size_t)-1;
        }
        for (size_t i = 0; i < le_produced; ++i) {
            uint16_t *w = (uint16_t *)*outbuf;
            uint16_t v = w[i];
            w[i] = (uint16_t)((v << 8) | (v >> 8));
        }
        *inbuf += *inbytesleft;
        *inbytesleft = 0;
        *outbuf += le_produced * sizeof(uint16_t);
        *outbytesleft -= le_produced * sizeof(uint16_t);
        produced = le_produced;
        break;
    }
    case WASI_ICONV_UTF16BE_TO_UTF8: {
        size_t units = *inbytesleft / sizeof(uint16_t);
        produced = utf16be_to_utf8((const uint16_t *)*inbuf, units, (uint8_t *)*outbuf, *outbytesleft);
        if (produced == (size_t)-1) {
            errno = E2BIG;
            return (size_t)-1;
        }
        *inbuf += units * sizeof(uint16_t);
        *inbytesleft -= units * sizeof(uint16_t);
        *outbuf += produced;
        *outbytesleft -= produced;
        break;
    }
    }
    return 0;
}

int iconv_close(iconv_t cd)
{
    free((struct wasi_iconv_desc *)cd);
    return 0;
}
