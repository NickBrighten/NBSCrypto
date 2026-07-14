//
//	sha1.c
//	Authors / Developers		: National Institute of Standards and Technology, National Security Agency
//	Last Modified (Original)	: 1993
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor sha1_desc =
{
    "sha1",
    194,
    20,
    64,
    &sha1_init,
    &sha1_process,
    &sha1_done,
    NULL
};




#pragma mark - DEFINES
#define F0(x,y,z) (z ^ (x & (y ^ z)))
#define F1(x,y,z) (x ^ y ^ z)
#define F2(x,y,z) ((x & y) | (z & (x | y)))
#define F3(x,y,z) (x ^ y ^ z)

#define STORE32H(x, y)										\
    do {(y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);	\
	(y)[2] = (unsigned char)(((x)>> 8)&255); (y)[3] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD32H(x, y)									\
    do {x = ((unsigned)((y)[0] & 255)<<24) | ((unsigned)((y)[1] & 255)<<16) |		\
	    ((unsigned)((y)[2] & 255)<< 8) | ((unsigned)((y)[3] & 255));		\
} while(0)

#define STORE64H(x, y)										\
    do {(y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);	\
	(y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);	\
	(y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);	\
	(y)[6] = (unsigned char)(((x)>> 8)&255); (y)[7] = (unsigned char)((x)&255);		\
} while(0)

#define ROL(x, y) ((((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)
#define ROLc(x, y) ((((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)

#define MIN(x, y) (((x)<(y))?(x):(y))




#pragma mark - INLINE
static inline int _sha1_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned a,b,c,d,e,W[80],i;

    for (i = 0; i < 16; i++) {
	LOAD32H(W[i], buf + (4*i));
    }

    a = hs->sha1.state[0];
    b = hs->sha1.state[1];
    c = hs->sha1.state[2];
    d = hs->sha1.state[3];
    e = hs->sha1.state[4];

    for (i = 16; i < 80; i++) {
	W[i] = ROL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    }

#define FF0(a,b,c,d,e,i) e = (ROLc(a, 5) + F0(b,c,d) + e + W[i] + 0x5a827999UL); b = ROLc(b, 30);
#define FF1(a,b,c,d,e,i) e = (ROLc(a, 5) + F1(b,c,d) + e + W[i] + 0x6ed9eba1UL); b = ROLc(b, 30);
#define FF2(a,b,c,d,e,i) e = (ROLc(a, 5) + F2(b,c,d) + e + W[i] + 0x8f1bbcdcUL); b = ROLc(b, 30);
#define FF3(a,b,c,d,e,i) e = (ROLc(a, 5) + F3(b,c,d) + e + W[i] + 0xca62c1d6UL); b = ROLc(b, 30);

    for (i = 0; i < 20; ) {
	FF0(a,b,c,d,e,i++);
	FF0(e,a,b,c,d,i++);
	FF0(d,e,a,b,c,i++);
	FF0(c,d,e,a,b,i++);
	FF0(b,c,d,e,a,i++);
    }

    /* round two */
    for (; i < 40; )  {
	FF1(a,b,c,d,e,i++);
	FF1(e,a,b,c,d,i++);
	FF1(d,e,a,b,c,i++);
	FF1(c,d,e,a,b,i++);
	FF1(b,c,d,e,a,i++);
    }

    /* round three */
    for (; i < 60; )  {
	FF2(a,b,c,d,e,i++);
	FF2(e,a,b,c,d,i++);
	FF2(d,e,a,b,c,i++);
	FF2(c,d,e,a,b,i++);
	FF2(b,c,d,e,a,i++);
    }

    /* round four */
    for (; i < 80; )  {
	FF3(a,b,c,d,e,i++);
	FF3(e,a,b,c,d,i++);
	FF3(d,e,a,b,c,i++);
	FF3(c,d,e,a,b,i++);
	FF3(b,c,d,e,a,i++);
    }

#undef FF0
#undef FF1
#undef FF2
#undef FF3

    hs->sha1.state[0] = hs->sha1.state[0] + a;
    hs->sha1.state[1] = hs->sha1.state[1] + b;
    hs->sha1.state[2] = hs->sha1.state[2] + c;
    hs->sha1.state[3] = hs->sha1.state[3] + d;
    hs->sha1.state[4] = hs->sha1.state[4] + e;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int sha1_init(hash_state *hs)
{
    hs->sha1.state[0] = 0x67452301UL;
    hs->sha1.state[1] = 0xefcdab89UL;
    hs->sha1.state[2] = 0x98badcfeUL;
    hs->sha1.state[3] = 0x10325476UL;
    hs->sha1.state[4] = 0xc3d2e1f0UL;
    hs->sha1.curlen = 0;
    hs->sha1.length = 0;
    return NBSCrypto_OK;
}

int sha1_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;
    if (hs->sha1.curlen > sizeof(hs->sha1.buf)) {
	return NBSCrypto_ERROR;
    }
    if ((hs->sha1.length + inlen * 8) < hs->sha1.length) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	if (hs->sha1.curlen == 0 && inlen >= 64) {
	    if ((err = _sha1_compress(hs, in)) != NBSCrypto_OK) {
		return err;
	    }
	    hs->sha1.length += 64 * 8;
	    in		+= 64;
	    inlen	-= 64;
	} else {
	    n = MIN(inlen, (64 - hs->sha1.curlen));
	    memcpy(hs->sha1.buf + hs->sha1.curlen, in, (size_t)n);
	    hs->sha1.curlen += n;
	    in += n;
	    inlen -= n;
	    if (hs->sha1.curlen == 64) {
		if ((err = _sha1_compress(hs, hs->sha1.buf)) != NBSCrypto_OK) {
		    return err;
		}
		hs->sha1.length += 64 * 8;
		hs->sha1.curlen = 0;
	    }
	}
    }
    return NBSCrypto_OK;
}

int sha1_done(hash_state *md, unsigned char *out)
{
    int i;

    if (md->sha1.curlen >= sizeof(md->sha1.buf)) {
	return NBSCrypto_ERROR;
    }

    md->sha1.length += md->sha1.curlen * 8;
    md->sha1.buf[md->sha1.curlen++] = (unsigned char)0x80;

    if (md->sha1.curlen > 56) {
	while (md->sha1.curlen < 64) {
	    md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
	}
	_sha1_compress(md, md->sha1.buf);
	md->sha1.curlen = 0;
    }

    while (md->sha1.curlen < 56) {
	md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
    }

    STORE64H(md->sha1.length, md->sha1.buf+56);
    _sha1_compress(md, md->sha1.buf);

    for (i = 0; i < 5; i++) {
	STORE32H(md->sha1.state[i], out+(4*i));
    }

    return NBSCrypto_OK;
}
