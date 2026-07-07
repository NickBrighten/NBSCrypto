//
//	poly1305.c
//

#include "nbs_crypto.h"




#pragma mark - DEFINES
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define LOAD32(p) (					\
    ((unsigned int)(((unsigned char *)(p))[0]) <<  0) |	\
    ((unsigned int)(((unsigned char *)(p))[1]) <<  8) |	\
    ((unsigned int)(((unsigned char *)(p))[2]) << 16) |	\
    ((unsigned int)(((unsigned char *)(p))[3]) << 24))

#define STORE32(a, p)							\
    ((unsigned char *)(p))[0] = ((unsigned int)(a) >>  0) & 0xFFU,	\
    ((unsigned char *)(p))[1] = ((unsigned int)(a) >>  8) & 0xFFU,	\
    ((unsigned char *)(p))[2] = ((unsigned int)(a) >> 16) & 0xFFU,	\
    ((unsigned char *)(p))[3] = ((unsigned int)(a) >> 24) & 0xFFU




#pragma mark - INLINE
static inline void _poly1305_processBlock(poly1305_state *poly1305)
{
    int n;
    unsigned long long temp;
    unsigned int u[8];

    n = poly1305->size;

    poly1305->buffer[n++] = 0x01;

    while(n < 17){
	poly1305->buffer[n++] = 0x00;
    }

    u[0] = LOAD32(poly1305->buffer);
    u[1] = LOAD32(poly1305->buffer + 4);
    u[2] = LOAD32(poly1305->buffer + 8);
    u[3] = LOAD32(poly1305->buffer + 12);
    u[4] = poly1305->buffer[16];

    temp  = (unsigned long long) poly1305->a[0] + u[0]; poly1305->a[0] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[1] + u[1]; poly1305->a[1] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[2] + u[2]; poly1305->a[2] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[3] + u[3]; poly1305->a[3] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[4] + u[4]; poly1305->a[4] = temp & 0xFFFFFFFF;

    temp  = (unsigned long long) poly1305->a[0] * poly1305->r[0]; u[0] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[0] * poly1305->r[1];
    temp += (unsigned long long) poly1305->a[1] * poly1305->r[0]; u[1] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[0] * poly1305->r[2];
    temp += (unsigned long long) poly1305->a[1] * poly1305->r[1];
    temp += (unsigned long long) poly1305->a[2] * poly1305->r[0]; u[2] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[0] * poly1305->r[3];
    temp += (unsigned long long) poly1305->a[1] * poly1305->r[2];
    temp += (unsigned long long) poly1305->a[2] * poly1305->r[1];
    temp += (unsigned long long) poly1305->a[3] * poly1305->r[0]; u[3] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[1] * poly1305->r[3];
    temp += (unsigned long long) poly1305->a[2] * poly1305->r[2];
    temp += (unsigned long long) poly1305->a[3] * poly1305->r[1];
    temp += (unsigned long long) poly1305->a[4] * poly1305->r[0]; u[4] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[2] * poly1305->r[3];
    temp += (unsigned long long) poly1305->a[3] * poly1305->r[2];
    temp += (unsigned long long) poly1305->a[4] * poly1305->r[1]; u[5] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[3] * poly1305->r[3];
    temp += (unsigned long long) poly1305->a[4] * poly1305->r[2]; u[6] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[4] * poly1305->r[3]; u[7] = temp & 0xFFFFFFFF;

    temp  = u[0]; temp += u[4] & 0xFFFFFFFC; temp += (u[4] >> 2) | (u[5] << 30); poly1305->a[0] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += u[1]; temp += u[5]; temp += (u[5] >> 2) | (u[6] << 30); poly1305->a[1] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += u[2]; temp += u[6]; temp += (u[6] >> 2) | (u[7] << 30); poly1305->a[2] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += u[3]; temp += u[7]; temp +=  u[7] >> 2; poly1305->a[3] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += u[4] & 0x00000003; poly1305->a[4] = temp & 0xFFFFFFFF;
}




#pragma mark - FUNCTIONS
int poly1305_init(const unsigned char *key, poly1305_state *poly1305)
{
    poly1305->r[0] = LOAD32(key);
    poly1305->r[1] = LOAD32(key +  4);
    poly1305->r[2] = LOAD32(key +  8);
    poly1305->r[3] = LOAD32(key + 12);
    poly1305->s[0] = LOAD32(key + 16);
    poly1305->s[1] = LOAD32(key + 20);
    poly1305->s[2] = LOAD32(key + 24);
    poly1305->s[3] = LOAD32(key + 28);

    poly1305->r[0] &= 0x0FFFFFFF;
    poly1305->r[1] &= 0x0FFFFFFC;
    poly1305->r[2] &= 0x0FFFFFFC;
    poly1305->r[3] &= 0x0FFFFFFC;

    poly1305->a[0] = 0;
    poly1305->a[1] = 0;
    poly1305->a[2] = 0;
    poly1305->a[3] = 0;
    poly1305->a[4] = 0;

    poly1305->size = 0;

    return NBSCrypto_OK;
}

int poly1305_process(const unsigned char *in, unsigned long inlen, poly1305_state *poly1305)
{
    unsigned long n;

    while(inlen > 0){
	n = MIN(inlen, 16 - poly1305->size);

	memcpy(poly1305->buffer + poly1305->size, in, n);

	poly1305->size += n;

	in = (unsigned char *) in + n;
	inlen -= n;

	if(poly1305->size == 16){
	    _poly1305_processBlock(poly1305);
	    poly1305->size = 0;
	}
    }

    return NBSCrypto_OK;
}

int poly1305_done(unsigned char *out, poly1305_state *poly1305)
{
    unsigned long long temp;
    unsigned int mask;
    unsigned int b[5];

    if(poly1305->size != 0)
    {
	_poly1305_processBlock(poly1305);
    }

    temp   = poly1305->a[4] & 0xFFFFFFFC;
    temp  += poly1305->a[4] >> 2;
    temp  += poly1305->a[0]; poly1305->a[0] = temp & 0xFFFFFFFF; temp >>= 32;
    temp  += poly1305->a[1]; poly1305->a[1] = temp & 0xFFFFFFFF; temp >>= 32;
    temp  += poly1305->a[2]; poly1305->a[2] = temp & 0xFFFFFFFF; temp >>= 32;
    temp  += poly1305->a[3]; poly1305->a[3] = temp & 0xFFFFFFFF; temp >>= 32;
    temp  += poly1305->a[4]; poly1305->a[4] = temp & 0x00000003;

    temp   = 5;
    temp  += poly1305->a[0]; b[0]   = temp & 0xFFFFFFFF; temp >>= 32;
    temp  += poly1305->a[1]; b[1]   = temp & 0xFFFFFFFF; temp >>= 32;
    temp  += poly1305->a[2]; b[2]   = temp & 0xFFFFFFFF; temp >>= 32;
    temp  += poly1305->a[3]; b[3]   = temp & 0xFFFFFFFF; temp >>= 32;
    temp  += poly1305->a[4]; b[4]   = temp & 0xFFFFFFFF;

    mask   = ((b[4] & 0x04) >> 2) - 1;

    poly1305->a[0] = (poly1305->a[0] & mask) | (b[0] & ~mask);
    poly1305->a[1] = (poly1305->a[1] & mask) | (b[1] & ~mask);
    poly1305->a[2] = (poly1305->a[2] & mask) | (b[2] & ~mask);
    poly1305->a[3] = (poly1305->a[3] & mask) | (b[3] & ~mask);

    temp  = (unsigned long long) poly1305->a[0] + poly1305->s[0]; b[0] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[1] + poly1305->s[1]; b[1] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[2] + poly1305->s[2]; b[2] = temp & 0xFFFFFFFF; temp >>= 32;
    temp += (unsigned long long) poly1305->a[3] + poly1305->s[3]; b[3] = temp & 0xFFFFFFFF;

    STORE32(b[0], out);
    STORE32(b[1], out +  4);
    STORE32(b[2], out +  8);
    STORE32(b[3], out + 12);

    poly1305->a[0] = 0;
    poly1305->a[1] = 0;
    poly1305->a[2] = 0;
    poly1305->a[3] = 0;
    poly1305->a[4] = 0;

    poly1305->r[0] = 0;
    poly1305->r[1] = 0;
    poly1305->r[2] = 0;
    poly1305->r[3] = 0;
    poly1305->s[0] = 0;
    poly1305->s[1] = 0;
    poly1305->s[2] = 0;
    poly1305->s[3] = 0;

    return NBSCrypto_OK;
}
