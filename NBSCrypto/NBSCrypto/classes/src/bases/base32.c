//
//	base32.c
//

#include "nbs_crypto.h"


int base32_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen, base32_alphabet id)
{
    unsigned long x;
    int y = 0;
    unsigned long long t = 0;
    char c;
    const unsigned char *map;
    const unsigned char tables[4][43] = {
	{  /* id = BASE32_RFC4648 : ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 */
	    99,99,26,27,28,29,30,31,99,99,99,99,99,99,99,99,99,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
	},
	{  /* id = BASE32_BASE32HEX : 0123456789ABCDEFGHIJKLMNOPQRSTUV */
	    0,1,2,3,4,5,6,7,8,9,99,99,99,99,99,99,99,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,99,99,99,99
	},
	{  /* id = BASE32_ZBASE32 : YBNDRFG8EJKMCPQXOT1UWISZA345H769 */
	    99,18,99,25,26,27,30,29,7,31,99,99,99,99,99,99,99,24,1,12,3,8,5,6,28,21,9,10,99,11,2,16,13,14,4,22,17,19,99,20,15,0,23
	},
	{  /* id = BASE32_CROCKFORD : 0123456789ABCDEFGHJKMNPQRSTVWXYZ + O=>0 + IL=>1 */
	    0,1,2,3,4,5,6,7,8,9,99,99,99,99,99,99,99,10,11,12,13,14,15,16,17,1,18,19,1,20,21,0,22,23,24,25,26,99,27,28,29,30,31
	    }
    };

    while (inlen > 0 && in[inlen-1] == '=') inlen--;

    if (inlen == 0) {
	*outlen = 0;
	return NBSCrypto_OK;
    }

    x = (inlen * 5) / 8;

    if (*outlen < x) {
	*outlen = x;
	return NBSCrypto_ERROR;
    }

    *outlen = x;

    x = inlen % 8;
    if (x == 1 || x == 3 || x == 6) {
	return NBSCrypto_ERROR;
    }

    map = tables[id];

    for (x = 0; x < inlen; x++) {
	c = in[x];

	if ((c >= 'a') && (c <= 'z')) c -= 32;

	if (c < '0' || c > 'Z' || map[c-'0'] > 31) {
	    return NBSCrypto_ERROR;
	}

	t = (t<<5) | map[c-'0'];

	if (++y == 8) {
	    *out++ = (unsigned char)((t>>32) & 255);
	    *out++ = (unsigned char)((t>>24) & 255);
	    *out++ = (unsigned char)((t>>16) & 255);
	    *out++ = (unsigned char)((t>> 8) & 255);
	    *out++ = (unsigned char)( t      & 255);
	    y = 0;
	    t = 0;
	}
    }

    if (y > 0) {
	t = t << (5 * (8 - y));
	if (y >= 2) *out++ = (unsigned char)((t>>32) & 255);
	if (y >= 4) *out++ = (unsigned char)((t>>24) & 255);
	if (y >= 5) *out++ = (unsigned char)((t>>16) & 255);
	if (y >= 7) *out++ = (unsigned char)((t>> 8) & 255);
    }
    return NBSCrypto_OK;
}

int base32_encode(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen, base32_alphabet id)
{
    unsigned long i, x;
    const char *codes;
    const char *alphabet[4] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",     /* id = BASE32_RFC4648   */
	"0123456789ABCDEFGHIJKLMNOPQRSTUV",     /* id = BASE32_BASE32HEX */
	"YBNDRFG8EJKMCPQXOT1UWISZA345H769",     /* id = BASE32_ZBASE32   */
	"0123456789ABCDEFGHJKMNPQRSTVWXYZ"      /* id = BASE32_CROCKFORD */
    };

    x = (8 * inlen + 4) / 5 + 1;

    if (*outlen < x) {
	*outlen = x;
	return NBSCrypto_ERROR;
    }

    *outlen = x - 1;

    if (inlen == 0) {
	*out = '\0';
	return NBSCrypto_OK;
    }

    codes = alphabet[id];
    x = 5 * (inlen / 5);

    for (i = 0; i < x; i += 5) {
	*out++ = codes[(in[0] >> 3) & 0x1F];
	*out++ = codes[(((in[0] & 0x7) << 2) + (in[1] >> 6)) & 0x1F];
	*out++ = codes[(in[1] >> 1) & 0x1F];
	*out++ = codes[(((in[1] & 0x1) << 4) + (in[2] >> 4)) & 0x1F];
	*out++ = codes[(((in[2] & 0xF) << 1) + (in[3] >> 7)) & 0x1F];
	*out++ = codes[(in[3] >> 2) & 0x1F];
	*out++ = codes[(((in[3] & 0x3) << 3) + (in[4] >> 5)) & 0x1F];
	*out++ = codes[in[4] & 0x1F];
	in += 5;
    }

    if (i < inlen) {
	unsigned a = in[0];
	unsigned b = (i+1 < inlen) ? in[1] : 0;
	unsigned c = (i+2 < inlen) ? in[2] : 0;
	unsigned d = (i+3 < inlen) ? in[3] : 0;
	*out++ = codes[(a >> 3) & 0x1F];
	*out++ = codes[(((a & 0x7) << 2) + (b >> 6)) & 0x1F];
	if (i+1 < inlen) {
	    *out++ = codes[(b >> 1) & 0x1F];
	    *out++ = codes[(((b & 0x1) << 4) + (c >> 4)) & 0x1F];
	}
	if (i+2 < inlen) {
	    *out++ = codes[(((c & 0xF) << 1) + (d >> 7)) & 0x1F];
	}
	if (i+3 < inlen) {
	    *out++ = codes[(d >> 2) & 0x1F];
	    *out++ = codes[((d & 0x3) << 3) & 0x1F];
	}
    }

    *out = '\0';

    return NBSCrypto_OK;
}
