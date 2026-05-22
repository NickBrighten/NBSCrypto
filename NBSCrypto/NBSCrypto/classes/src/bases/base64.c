//
//	base64.c
//

#include "nbs_crypto.h"


static const unsigned char _mbase64[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 253, 255, 255, 253, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
     52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 254, 255, 255,
    255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
     41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};

static const unsigned char _mbase64url[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 253, 255, 255, 253, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255, 255,
     52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 254, 255, 255,
    255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255,  63,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
     41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};

static const char* const _cbase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char* const _cbase64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

enum {
    insane 	= 0,
    strict	= 1,
    relaxed	= 2
};

#pragma mark - BASE64 - Decode
static inline int _base64_decode_internal(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen, const unsigned char *map, int mode)
{
    unsigned long t, x, y, z;
    unsigned char c;
    int           g;

    g = 0;
    for (x = y = z = t = 0; x < inlen; x++) {
	if ((in[x] == 0) && (x == (inlen - 1)) && (mode != strict)) {
	    continue;
	}
	c = map[(unsigned char)in[x]&0xFF];
	if (c == 254) {
	    g++;
	    continue;
	}
	if (c == 253) {
	    if (mode == strict) {
		 return NBSCrypto_ERROR;
	    }
	    continue;
	}
	if (c == 255) {
	    if (mode == insane) {
		 continue;
	    }
	    return NBSCrypto_ERROR;
	}
	if ((g > 0) && (mode != insane)) {
	    return NBSCrypto_ERROR;
	}

	t = (t<<6)|c;

	if (++y == 4) {
	    if (z + 3 > *outlen) return NBSCrypto_ERROR;
	    out[z++] = (unsigned char)((t>>16)&255);
	    out[z++] = (unsigned char)((t>>8)&255);
	    out[z++] = (unsigned char)(t&255);
	    y = t = 0;
	 }
    }

    if (y != 0) {
	if (y == 1) return NBSCrypto_ERROR;
	if (((y + g) != 4) && (mode == strict) && (map != _mbase64url)) return NBSCrypto_ERROR;
	t = t << (6 * (4 - y));
	if (z + y - 1 > *outlen) return NBSCrypto_ERROR;
	if (y >= 2) out[z++] = (unsigned char) ((t >> 16) & 255);
	if (y == 3) out[z++] = (unsigned char) ((t >> 8) & 255);
    }
    *outlen = z;
    return NBSCrypto_OK;
}

int base64_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen) {
    return _base64_decode_internal(in, inlen, out, outlen, _mbase64, insane);
}
int base64_strict_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen) {
    return _base64_decode_internal(in, inlen, out, outlen, _mbase64, strict);
}
int base64_sane_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen) {
    return _base64_decode_internal(in, inlen, out, outlen, _mbase64, relaxed);
}
int base64url_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen) {
    return _base64_decode_internal(in, inlen, out, outlen, _mbase64url, insane);
}
int base64url_strict_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen) {
    return _base64_decode_internal(in, inlen, out, outlen, _mbase64url, strict);
}
int base64url_sane_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen) {
    return _base64_decode_internal(in, inlen, out, outlen, _mbase64url, relaxed);
}

#pragma mark - BASE64 - Encode
static inline int _base64_encode_internal(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen, const char *codes, int pad)
{
    unsigned long i, len2, leven;
    char *p;

    len2 = 4 * ((inlen + 2) / 3);
    if (*outlen < len2 + 1) {
	*outlen = len2 + 1;
	return NBSCrypto_ERROR;
    }

    p = out;
    leven = 3*(inlen / 3);

    for (i = 0; i < leven; i += 3) {
	*p++ = codes[(in[0] >> 2) & 0x3F];
	*p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
	*p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
	*p++ = codes[in[2] & 0x3F];
	in += 3;
    }

    if (i < inlen) {
	unsigned a = in[0];
	unsigned b = (i+1 < inlen) ? in[1] : 0;

	*p++ = codes[(a >> 2) & 0x3F];
	*p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
	if (pad) {
	    *p++ = (i+1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
	    *p++ = '=';
	}
	else {
	    if (i+1 < inlen) *p++ = codes[(((b & 0xf) << 2)) & 0x3F];
	}
    }

    *p = '\0';

    *outlen = (unsigned long)(p - out);

    return NBSCrypto_OK;
}

int base64_encode(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen) {
    return _base64_encode_internal(in, inlen, out, outlen, _cbase64, 1);
}
int base64url_encode(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen) {
    return _base64_encode_internal(in, inlen, out, outlen, _cbase64url, 0);
}
int base64url_strict_encode(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen) {
    return _base64_encode_internal(in, inlen, out, outlen, _cbase64url, 1);
}
