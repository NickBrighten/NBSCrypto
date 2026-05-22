//
//	md4.c
//	Authors / Developers		: Ronald L. Rivest
//	Last Modified (Original)	: 1990
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor md4_desc =
{
    "md4",
    168,
    16,
    64,
    &md4_init,
    &md4_process,
    &md4_done,
    NULL
};




#pragma mark - DEFINES
#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15

#define F(x, y, z) (z ^ (x & (y ^ z)))
#define G(x, y, z) ((x & y) | (z & (x | y)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define ROTATE_LEFT(x, n) ROLc(x, n)

#define FF(a, b, c, d, x, s) {(a) += F ((b), (c), (d)) + (x); (a) = ROTATE_LEFT ((a), (s));}
#define GG(a, b, c, d, x, s) {(a) += G ((b), (c), (d)) + (x) + 0x5a827999UL; (a) = ROTATE_LEFT ((a), (s));}
#define HH(a, b, c, d, x, s) {(a) += H ((b), (c), (d)) + (x) + 0x6ed9eba1UL; (a) = ROTATE_LEFT ((a), (s));}

#define STORE32L(x, y)										\
    do {											\
	(y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);	\
	(y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255);		\
    } while(0)

#define LOAD32L(x, y)										\
    do {x = ((unsigned)((y)[3] & 255)<<24) | ((unsigned)((y)[2] & 255)<<16) |			\
	((unsigned)((y)[1] & 255)<<8)  | ((unsigned)((y)[0] & 255));				\
    } while(0)

#define STORE64L(x,y)										\
    do {(y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);	\
	(y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);	\
	(y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);	\
	(y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255);		\
    } while(0)

#define ROLc(x, y) ((((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)

#define MIN(x, y) (((x)<(y))?(x):(y))




#pragma mark - INLINE
static inline int _md4_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned x[16], a, b, c, d;
    int i;

    a = hs->md4.state[0];
    b = hs->md4.state[1];
    c = hs->md4.state[2];
    d = hs->md4.state[3];

    for (i = 0; i < 16; i++) {
	LOAD32L(x[i], buf + (4*i));
    }

    /* Round 1 */
    FF (a, b, c, d, x[ 0], S11); /* 1 */
    FF (d, a, b, c, x[ 1], S12); /* 2 */
    FF (c, d, a, b, x[ 2], S13); /* 3 */
    FF (b, c, d, a, x[ 3], S14); /* 4 */
    FF (a, b, c, d, x[ 4], S11); /* 5 */
    FF (d, a, b, c, x[ 5], S12); /* 6 */
    FF (c, d, a, b, x[ 6], S13); /* 7 */
    FF (b, c, d, a, x[ 7], S14); /* 8 */
    FF (a, b, c, d, x[ 8], S11); /* 9 */
    FF (d, a, b, c, x[ 9], S12); /* 10 */
    FF (c, d, a, b, x[10], S13); /* 11 */
    FF (b, c, d, a, x[11], S14); /* 12 */
    FF (a, b, c, d, x[12], S11); /* 13 */
    FF (d, a, b, c, x[13], S12); /* 14 */
    FF (c, d, a, b, x[14], S13); /* 15 */
    FF (b, c, d, a, x[15], S14); /* 16 */

    /* Round 2 */
    GG (a, b, c, d, x[ 0], S21); /* 17 */
    GG (d, a, b, c, x[ 4], S22); /* 18 */
    GG (c, d, a, b, x[ 8], S23); /* 19 */
    GG (b, c, d, a, x[12], S24); /* 20 */
    GG (a, b, c, d, x[ 1], S21); /* 21 */
    GG (d, a, b, c, x[ 5], S22); /* 22 */
    GG (c, d, a, b, x[ 9], S23); /* 23 */
    GG (b, c, d, a, x[13], S24); /* 24 */
    GG (a, b, c, d, x[ 2], S21); /* 25 */
    GG (d, a, b, c, x[ 6], S22); /* 26 */
    GG (c, d, a, b, x[10], S23); /* 27 */
    GG (b, c, d, a, x[14], S24); /* 28 */
    GG (a, b, c, d, x[ 3], S21); /* 29 */
    GG (d, a, b, c, x[ 7], S22); /* 30 */
    GG (c, d, a, b, x[11], S23); /* 31 */
    GG (b, c, d, a, x[15], S24); /* 32 */

    /* Round 3 */
    HH (a, b, c, d, x[ 0], S31); /* 33 */
    HH (d, a, b, c, x[ 8], S32); /* 34 */
    HH (c, d, a, b, x[ 4], S33); /* 35 */
    HH (b, c, d, a, x[12], S34); /* 36 */
    HH (a, b, c, d, x[ 2], S31); /* 37 */
    HH (d, a, b, c, x[10], S32); /* 38 */
    HH (c, d, a, b, x[ 6], S33); /* 39 */
    HH (b, c, d, a, x[14], S34); /* 40 */
    HH (a, b, c, d, x[ 1], S31); /* 41 */
    HH (d, a, b, c, x[ 9], S32); /* 42 */
    HH (c, d, a, b, x[ 5], S33); /* 43 */
    HH (b, c, d, a, x[13], S34); /* 44 */
    HH (a, b, c, d, x[ 3], S31); /* 45 */
    HH (d, a, b, c, x[11], S32); /* 46 */
    HH (c, d, a, b, x[ 7], S33); /* 47 */
    HH (b, c, d, a, x[15], S34); /* 48 */

    hs->md4.state[0] = hs->md4.state[0] + a;
    hs->md4.state[1] = hs->md4.state[1] + b;
    hs->md4.state[2] = hs->md4.state[2] + c;
    hs->md4.state[3] = hs->md4.state[3] + d;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int md4_init(hash_state *hs)
{
    hs->md4.state[0] = 0x67452301UL;
    hs->md4.state[1] = 0xefcdab89UL;
    hs->md4.state[2] = 0x98badcfeUL;
    hs->md4.state[3] = 0x10325476UL;
    hs->md4.length  = 0;
    hs->md4.curlen  = 0;
    return NBSCrypto_OK;
}

int md4_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;
    if (hs->md4.curlen > sizeof(hs->md4.buf)) {
	return NBSCrypto_ERROR;
    }
    if ((hs->md4.length + inlen * 8) < hs->md4.length) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	if (hs->md4.curlen == 0 && inlen >= 64) {
	    if ((err = _md4_compress(hs, in)) != NBSCrypto_OK) {
		return err;
	    }
	    hs->md4.length += 64 * 8;
	    in		+= 64;
	    inlen	-= 64;
	} else {
	    n = MIN(inlen, (64 - hs->md4.curlen));
	    memcpy(hs->md4.buf + hs->md4.curlen, in, (size_t)n);
	    hs->md4.curlen += n;
	    in += n;
	    inlen -= n;
	    if (hs->md4.curlen == 64) {
		if ((err = _md4_compress(hs, hs->md4.buf)) != NBSCrypto_OK) {
		    return err;
		}
		hs->md4.length += 64 * 8;
		hs->md4.curlen = 0;
	    }
	}
    }
    return NBSCrypto_OK;
}

int md4_done(hash_state *hs, unsigned char *out)
{
    int i;

    if (hs->md4.curlen >= sizeof(hs->md4.buf)) {
	return NBSCrypto_ERROR;
    }

    hs->md4.length += hs->md4.curlen * 8;
    hs->md4.buf[hs->md4.curlen++] = (unsigned char)0x80;

    if (hs->md4.curlen > 56) {
	while (hs->md4.curlen < 64) {
	    hs->md4.buf[hs->md4.curlen++] = (unsigned char)0;
	}
	_md4_compress(hs, hs->md4.buf);
	hs->md4.curlen = 0;
    }

    while (hs->md4.curlen < 56) {
	hs->md4.buf[hs->md4.curlen++] = (unsigned char)0;
    }

    STORE64L(hs->md4.length, hs->md4.buf+56);
    _md4_compress(hs, hs->md4.buf);

    for (i = 0; i < 4; i++) {
	STORE32L(hs->md4.state[i], out+(4*i));
    }

    return NBSCrypto_OK;
}
