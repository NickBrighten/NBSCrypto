//
//	rc4.c
//	Authors / Developers		: Ronald L. Rivest
//	Last Modified (Original)	: 1987
//


#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor rc4_desc =
{
    "rc4",
    25,
    1, 256, 0, 0,
    NULL,
    NULL,
    NULL,
    NULL
};




#pragma mark - INLINE
static inline int _rc4_crypt(const unsigned char *in, unsigned char *out, unsigned long len, cipher_state *cs)
{
    unsigned char x, y, *s, tmp;

    x = cs->rc4.x;
    y = cs->rc4.y;
    s = cs->rc4.buf;
    while (len--) {
	x = (x + 1) & 255;
	y = (y + s[x]) & 255;
	tmp = s[x]; s[x] = s[y]; s[y] = tmp;
	tmp = (s[x] + s[y]) & 255;
	*out++ = *in++ ^ s[tmp];
    }
    cs->rc4.x = x;
    cs->rc4.y = y;
    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int rc4_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    int x, y;
    unsigned char tmp, *s;
    unsigned long j;

    if (keylen > 256) {keylen = 256;}
    if (keylen < 1) {keylen = 1;}

    s = cs->rc4.buf;
    for (x = 0; x < 256; x++) {
	s[x] = x;
    }

    for (j = x = y = 0; x < 256; x++) {
	y = (y + s[x] + key[j++]) & 255;
	if (j == keylen) {
	    j = 0;
	}
	tmp = s[x]; s[x] = s[y]; s[y] = tmp;
    }
    cs->rc4.x = 0;
    cs->rc4.y = 0;

    return NBSCrypto_OK;
}

int rc4_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cipher_state *cs)
{
    return _rc4_crypt(pt, ct, len, cs);
}

int rc4_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cipher_state *cs)
{
    return _rc4_crypt(ct, pt, len, cs);
}

void rc4_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->rc4));
}

