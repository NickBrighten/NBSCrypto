//
//	md5.c
//	Authors / Developers		: Ronald L. Rivest
//	Last Modified (Original)	: 1991
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor md5_desc =
{
    "md5",
    169,
    16,
    64,
    &md5_init,
    &md5_process,
    &md5_done,
    NULL
};




#pragma mark - DEFINES
#define F(x,y,z)  (z ^ (x & (y ^ z)))
#define G(x,y,z)  (y ^ (z & (y ^ x)))
#define H(x,y,z)  (x^y^z)
#define I(x,y,z)  (y^(x|(~z)))

#define FF(a,b,c,d,M,s,t) a = (a + F(b,c,d) + M + t); a = ROLc(a, s) + b;
#define GG(a,b,c,d,M,s,t) a = (a + G(b,c,d) + M + t); a = ROLc(a, s) + b;
#define HH(a,b,c,d,M,s,t) a = (a + H(b,c,d) + M + t); a = ROLc(a, s) + b;
#define II(a,b,c,d,M,s,t) a = (a + I(b,c,d) + M + t); a = ROLc(a, s) + b;

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
static inline int _md5_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned i, W[16], a, b, c, d;

    for (i = 0; i < 16; i++) {
	LOAD32L(W[i], buf + (4*i));
    }

    a = hs->md5.state[0];
    b = hs->md5.state[1];
    c = hs->md5.state[2];
    d = hs->md5.state[3];

    FF(a,b,c,d,W[0],7,0xd76aa478UL)
    FF(d,a,b,c,W[1],12,0xe8c7b756UL)
    FF(c,d,a,b,W[2],17,0x242070dbUL)
    FF(b,c,d,a,W[3],22,0xc1bdceeeUL)
    FF(a,b,c,d,W[4],7,0xf57c0fafUL)
    FF(d,a,b,c,W[5],12,0x4787c62aUL)
    FF(c,d,a,b,W[6],17,0xa8304613UL)
    FF(b,c,d,a,W[7],22,0xfd469501UL)
    FF(a,b,c,d,W[8],7,0x698098d8UL)
    FF(d,a,b,c,W[9],12,0x8b44f7afUL)
    FF(c,d,a,b,W[10],17,0xffff5bb1UL)
    FF(b,c,d,a,W[11],22,0x895cd7beUL)
    FF(a,b,c,d,W[12],7,0x6b901122UL)
    FF(d,a,b,c,W[13],12,0xfd987193UL)
    FF(c,d,a,b,W[14],17,0xa679438eUL)
    FF(b,c,d,a,W[15],22,0x49b40821UL)
    GG(a,b,c,d,W[1],5,0xf61e2562UL)
    GG(d,a,b,c,W[6],9,0xc040b340UL)
    GG(c,d,a,b,W[11],14,0x265e5a51UL)
    GG(b,c,d,a,W[0],20,0xe9b6c7aaUL)
    GG(a,b,c,d,W[5],5,0xd62f105dUL)
    GG(d,a,b,c,W[10],9,0x02441453UL)
    GG(c,d,a,b,W[15],14,0xd8a1e681UL)
    GG(b,c,d,a,W[4],20,0xe7d3fbc8UL)
    GG(a,b,c,d,W[9],5,0x21e1cde6UL)
    GG(d,a,b,c,W[14],9,0xc33707d6UL)
    GG(c,d,a,b,W[3],14,0xf4d50d87UL)
    GG(b,c,d,a,W[8],20,0x455a14edUL)
    GG(a,b,c,d,W[13],5,0xa9e3e905UL)
    GG(d,a,b,c,W[2],9,0xfcefa3f8UL)
    GG(c,d,a,b,W[7],14,0x676f02d9UL)
    GG(b,c,d,a,W[12],20,0x8d2a4c8aUL)
    HH(a,b,c,d,W[5],4,0xfffa3942UL)
    HH(d,a,b,c,W[8],11,0x8771f681UL)
    HH(c,d,a,b,W[11],16,0x6d9d6122UL)
    HH(b,c,d,a,W[14],23,0xfde5380cUL)
    HH(a,b,c,d,W[1],4,0xa4beea44UL)
    HH(d,a,b,c,W[4],11,0x4bdecfa9UL)
    HH(c,d,a,b,W[7],16,0xf6bb4b60UL)
    HH(b,c,d,a,W[10],23,0xbebfbc70UL)
    HH(a,b,c,d,W[13],4,0x289b7ec6UL)
    HH(d,a,b,c,W[0],11,0xeaa127faUL)
    HH(c,d,a,b,W[3],16,0xd4ef3085UL)
    HH(b,c,d,a,W[6],23,0x04881d05UL)
    HH(a,b,c,d,W[9],4,0xd9d4d039UL)
    HH(d,a,b,c,W[12],11,0xe6db99e5UL)
    HH(c,d,a,b,W[15],16,0x1fa27cf8UL)
    HH(b,c,d,a,W[2],23,0xc4ac5665UL)
    II(a,b,c,d,W[0],6,0xf4292244UL)
    II(d,a,b,c,W[7],10,0x432aff97UL)
    II(c,d,a,b,W[14],15,0xab9423a7UL)
    II(b,c,d,a,W[5],21,0xfc93a039UL)
    II(a,b,c,d,W[12],6,0x655b59c3UL)
    II(d,a,b,c,W[3],10,0x8f0ccc92UL)
    II(c,d,a,b,W[10],15,0xffeff47dUL)
    II(b,c,d,a,W[1],21,0x85845dd1UL)
    II(a,b,c,d,W[8],6,0x6fa87e4fUL)
    II(d,a,b,c,W[15],10,0xfe2ce6e0UL)
    II(c,d,a,b,W[6],15,0xa3014314UL)
    II(b,c,d,a,W[13],21,0x4e0811a1UL)
    II(a,b,c,d,W[4],6,0xf7537e82UL)
    II(d,a,b,c,W[11],10,0xbd3af235UL)
    II(c,d,a,b,W[2],15,0x2ad7d2bbUL)
    II(b,c,d,a,W[9],21,0xeb86d391UL)

    hs->md5.state[0] = hs->md5.state[0] + a;
    hs->md5.state[1] = hs->md5.state[1] + b;
    hs->md5.state[2] = hs->md5.state[2] + c;
    hs->md5.state[3] = hs->md5.state[3] + d;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int md5_init(hash_state *hs)
{
    hs->md5.state[0] = 0x67452301UL;
    hs->md5.state[1] = 0xefcdab89UL;
    hs->md5.state[2] = 0x98badcfeUL;
    hs->md5.state[3] = 0x10325476UL;
    hs->md5.curlen = 0;
    hs->md5.length = 0;
    return NBSCrypto_OK;
}

int md5_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;
    if (hs->md5.curlen > sizeof(hs->md5.buf)) {
	return NBSCrypto_ERROR;
    }
    if ((hs->md5.length + inlen * 8) < hs->md5.length) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	if (hs->md5.curlen == 0 && inlen >= 64) {
	    if ((err = _md5_compress(hs, in)) != NBSCrypto_OK) {
		return err;
	    }
	    hs->md5.length += 64 * 8;
	    in		+= 64;
	    inlen	-= 64;
	} else {
	    n = MIN(inlen, (64 - hs->md5.curlen));
	    memcpy(hs->md5.buf + hs->md5.curlen, in, (size_t)n);
	    hs->md5.curlen += n;
	    in += n;
	    inlen -= n;
	    if (hs->md5.curlen == 64) {
		if ((err = _md5_compress(hs, hs->md5.buf)) != NBSCrypto_OK) {
		    return err;
		}
		hs->md5.length += 64 * 8;
		hs->md5.curlen = 0;
	    }
	}
    }
    return NBSCrypto_OK;
}

int md5_done(hash_state *hs, unsigned char *out)
{
    int i;

    if (hs->md5.curlen >= sizeof(hs->md5.buf)) {
	return NBSCrypto_ERROR;
    }

    hs->md5.length += hs->md5.curlen * 8;
    hs->md5.buf[hs->md5.curlen++] = (unsigned char)0x80;

    if (hs->md5.curlen > 56) {
	while (hs->md5.curlen < 64) {
	    hs->md5.buf[hs->md5.curlen++] = (unsigned char)0;
	}
	_md5_compress(hs, hs->md5.buf);
	hs->md5.curlen = 0;
    }

    while (hs->md5.curlen < 56) {
	hs->md5.buf[hs->md5.curlen++] = (unsigned char)0;
    }

    STORE64L(hs->md5.length, hs->md5.buf+56);
    _md5_compress(hs, hs->md5.buf);

    for (i = 0; i < 4; i++) {
	STORE32L(hs->md5.state[i], out+(4*i));
    }

    return NBSCrypto_OK;
}
