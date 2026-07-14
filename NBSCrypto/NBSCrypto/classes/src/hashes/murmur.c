//
//	murmur.c
//	Authors / Developers		: Austin Appleby
//	Last Modified (Original)	: April 3, 2011
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor murmur3a_desc =
{
    "murmur3a",
    187,
    4,
    4,
    &murmur3a_init,
    &murmur3a_process,
    &murmur3a_done,
    NULL
};

const struct hash_descriptor murmur3c_desc =
{
    "murmur3c",
    188,
    16,
    16,
    &murmur3c_init,
    &murmur3c_process,
    &murmur3c_done,
    NULL
};

const struct hash_descriptor murmur3f_desc =
{
    "murmur3f",
    189,
    16,
    16,
    &murmur3f_init,
    &murmur3f_process,
    &murmur3f_done,
    NULL
};




#pragma mark - DEFINES
#define MURMUR3A_SPEC "lll"
#define MURMUR3C_SPEC "lllllllll"
#define MURMUR3F_SPEC "qqqql"

#define BIG_CONSTANT(x) (x##LLU)

#define ROTL32(x,r) (((unsigned)x << r) | ((unsigned)x >> (32 - r)))
#define ROTL64(x,r) (((unsigned long long)x << r) | ((unsigned long long)x >> (64 - r)))

#define READ_32(ptr,i) _getblock32((unsigned *)ptr,i)
#define READ_64(ptr,i) _getblock64((unsigned long long *)ptr,i)

#define doblock(h1, k1) do {	\
    k1 *= kC1_32;		\
    k1 = ROTL32(k1,15);		\
    k1 *= kC2_32;		\
    h1 ^= k1;			\
    h1 = ROTL32(h1,13);		\
    h1 = h1*5+0xe6546b64;	\
} while(0)

#define dobytes(cnt, h1, c, n, ptr, len) do {	\
    unsigned __cnt = cnt;			\
    while(__cnt--) {				\
	c = c>>8 | (unsigned)*ptr++<<24;	\
	n++;					\
	len--;					\
	if(n==4) {				\
	    doblock(h1, c);			\
	    n = 0;				\
	}					\
    }						\
} while(0)

#define doblock128x64(h1, h2, k1, k2) do {	\
    k1 *= kC1L;					\
    k1  = ROTL64(k1,31);			\
    k1 *= kC2L;					\
    h1 ^= k1;					\
    h1 = ROTL64(h1,27);				\
    h1 += h2;					\
    h1 = h1*5+0x52dce729;			\
    k2 *= kC2L;					\
    k2  = ROTL64(k2,33);			\
    k2 *= kC1L;					\
    h2 ^= k2;					\
    h2 = ROTL64(h2,31);				\
    h2 += h1;					\
    h2 = h2*5+0x38495ab5;			\
} while(0)

#define doblock128x86(h1, h2, h3, h4, k1, k2, k3,k4) do {	\
    k1 *= kC1_64;						\
    k1  = ROTL32(k1,15);					\
    k1 *= kC2_64;						\
    h1 ^= k1;							\
    h1 = ROTL32(h1,19);						\
    h1 += h2;							\
    h1 = h1*5+0x561ccd1b;					\
    k2 *= kC2_64;						\
    k2  = ROTL32(k2,16);					\
    k2 *= kC3_64;						\
    h2 ^= k2;							\
    h2 = ROTL32(h2,17);						\
    h2 += h3;							\
    h2 = h2*5+0x0bcaa747;					\
    k3 *= kC3_64;						\
    k3  = ROTL32(k3,17);					\
    k3 *= kC4_64;						\
    h3 ^= k3;							\
    h3 = ROTL32(h3,15);						\
    h3 += h4;							\
    h3 = h3*5+0x96cd1c35;					\
    k4 *= kC4_64;						\
    k4  = ROTL32(k4,18);					\
    k4 *= kC1_64;						\
    h4 ^= k4;							\
    h4 = ROTL32(h4,13);						\
    h4 += h1;							\
    h4 = h4*5+0x32ac3b17;					\
} while(0)

#define dobytes128x64(cnt, h1, h2, k1, k2, n, ptr, len)	do {				\
    unsigned __cnt = cnt;								\
    for(;__cnt--; len--) {								\
	switch(n) {									\
	    case  0: case  1: case  2: case  3: case  4: case  5: case  6: case  7:	\
		k1 = k1>>8 | (unsigned long long)*ptr++<<56;				\
		n++;									\
		break;									\
	    case  8: case  9: case 10: case 11: case 12: case 13: case 14:		\
		k2 = k2>>8 | (unsigned long long)*ptr++<<56;				\
		n++;									\
		break;									\
	    case 15:									\
		k2 = k2>>8 | (unsigned long long)*ptr++<<56;				\
		doblock128x64(h1, h2, k1, k2);						\
		n = 0;									\
		break;									\
	}										\
    }											\
} while(0)

#define dobytes128x86(cnt, h1, h2, h3, h4, k1, k2, k3, k4, n, ptr, len)	do {	\
    unsigned __cnt = cnt;							\
    for(;__cnt--; len--){							\
	switch(n){								\
	    case  0: case  1: case  2: case  3:					\
		k1 = k1>>8 | (unsigned)*ptr++<<24;				\
		++n;								\
		break;								\
	    case  4: case  5: case  6: case  7:					\
		k2 = k2>>8 | (unsigned)*ptr++<<24;				\
		++n;								\
		break;								\
	    case  8: case  9: case 10: case 11:					\
		k3 = k3>>8 | (unsigned)*ptr++<<24;				\
		++n;								\
		break;								\
	    case 12: case 13: case 14:						\
		k4 = k4>>8 | (unsigned)*ptr++<<24;				\
		++n;								\
		break;								\
	    case 15:								\
		k4 = k4>>8 | (unsigned)*ptr++<<24;				\
		doblock128x86(h1, h2, h3, h4, k1, k2, k3, k4);			\
		n = 0;								\
		break;								\
	}									\
    }										\
} while(0)


static const unsigned kC1_32 = 0xcc9e2d51;
static const unsigned kC2_32 = 0x1b873593;
static const unsigned kC1_64 = 0x239b961b;
static const unsigned kC2_64 = 0xab0e9789;
static const unsigned kC3_64 = 0x38b34ae5;
static const unsigned kC4_64 = 0xa1e38b93;
static const unsigned long long kC1L = BIG_CONSTANT(0x87c37b91114253d5);
static const unsigned long long kC2L = BIG_CONSTANT(0x4cf5ad432745937f);




#pragma mark - INLINE
static inline unsigned _fmix32(unsigned h)
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}

static inline unsigned long long _fmix64(unsigned long long k)
{
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;

    return k;
}

static inline unsigned _getblock32(const unsigned *const p, const int i)
{
    return p[i];
}

static inline unsigned long long _getblock64(const unsigned long long *const p, const int i)
{
    return p[i];
}

static inline void _murmur32_process(unsigned *ph1, unsigned *pcarry, const void *key, int len)
{
    unsigned h1 = *ph1;
    unsigned c = *pcarry;

    const unsigned char *ptr = (unsigned char *)key;
    const unsigned char *end;

    int n = c & 3;

    int i = -(intptr_t)(void *)ptr & 3;
    if(i && i <= len) {
	dobytes(i, h1, c, n, ptr, len);
    }

    end = ptr + (len & ~3);
    switch(n) {
	case 0:
	    for( ; ptr < end ; ptr+=4) {
		unsigned k1 = READ_32(ptr,0);
		doblock(h1, k1);
	    }
	    break;
	case 1:
	    for( ; ptr < end ; ptr+=4) {
		unsigned k1 = c>>24;
		c = READ_32(ptr,0);
		k1 |= c<<8;
		doblock(h1, k1);
	    }
	    break;
	case 2:
	    for( ; ptr < end ; ptr+=4) {
		unsigned k1 = c>>16;
		c = READ_32(ptr,0);
		k1 |= c<<16;
		doblock(h1, k1);
	    }
	    break;
	case 3:
	    for( ; ptr < end ; ptr+=4) {
		unsigned k1 = c>>8;
		c = READ_32(ptr,0);
		k1 |= c<<24;
		doblock(h1, k1);
	    }
    }

    len -= len & ~3;

    dobytes(len, h1, c, n, ptr, len);

    *ph1 = h1;
    *pcarry = (c & ~0xff) | n;
}

static inline unsigned _murmur32_result(unsigned h, unsigned carry, unsigned total_length)
{
    unsigned k1;
    int n = carry & 3;
    if(n) {
	k1 = carry >> (4-n)*8;
	k1 *= kC1_32; k1 = ROTL32(k1,15); k1 *= kC2_32; h ^= k1;
    }
    h ^= total_length;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}

static inline void _murmur128x64_result(const unsigned long long ph[2], const unsigned long long pcarry[2], const unsigned total_length, unsigned long long out[2])
{
    unsigned long long h1 = ph[0];
    unsigned long long h2 = ph[1];

    unsigned long long k1;
    unsigned long long k2 = pcarry[1];

    int n = k2 & 15;
    if (n) {
	k1 = pcarry[0];
	if (n > 8) {
	    k2 >>= (16-n)*8;
	    k2 *= kC2L; k2  = ROTL64(k2,33); k2 *= kC1L; h2 ^= k2;
	} else {
	    k1 >>= (8-n)*8;
	}
	k1 *= kC1L; k1  = ROTL64(k1,31); k1 *= kC2L; h1 ^= k1;
    }

    h1 ^= total_length; h2 ^= total_length;
    h1 += h2;
    h2 += h1;
    h1 = _fmix64(h1);
    h2 = _fmix64(h2);
    h1 += h2;
    h2 += h1;

    out[0] = h1;
    out[1] = h2;
}

static inline void _murmur128x86_result(const unsigned ph[4], const unsigned pcarry[4], unsigned total_length, unsigned out[4])
{
    unsigned h1 = ph[0];
    unsigned h2 = ph[1];
    unsigned h3 = ph[2];
    unsigned h4 = ph[3];
    unsigned k1, k2, k3, k4 = pcarry[3];

    int n = k4 & 15;
    switch(n) {
	case  1: case  2: case  3: case  4:
	    k1 = pcarry[0] >> (4-n)*8;
	    goto finrot_k1;

	case  5: case  6: case  7: case  8:
	    k2 = pcarry[1] >> (8-n)*8;
	    goto finrot_k21;

	case  9: case 10: case 11: case 12:
	    k3 = pcarry[2] >> (12-n)*8;
	    goto finrot_k321;

	case 13: case 14: case 15:
	    k4 >>= (16-n)*8;
	    goto finrot_k4321;

	default:
	    goto skiprot;
    }
finrot_k4321:
    k4 *= kC4_64; k4  = ROTL32(k4,18); k4 *= kC1_64; h4 ^= k4;
    k3 = pcarry[2];
finrot_k321:
    k3 *= kC3_64; k3  = ROTL32(k3,17); k3 *= kC4_64; h3 ^= k3;
    k2 = pcarry[1];
finrot_k21:
    k2 *= kC2_64; k2  = ROTL32(k2,16); k2 *= kC3_64; h2 ^= k2;
    k1 = pcarry[0];
finrot_k1:
    k1 *= kC1_64; k1  = ROTL32(k1,15); k1 *= kC2_64; h1 ^= k1;
skiprot:

    h1 ^= total_length; h2 ^= total_length;
    h3 ^= total_length; h4 ^= total_length;
    h1 += h2; h1 += h3; h1 += h4;
    h2 += h1; h3 += h1; h4 += h1;
    h1 = _fmix32(h1);
    h2 = _fmix32(h2);
    h3 = _fmix32(h3);
    h4 = _fmix32(h4);
    h1 += h2; h1 += h3; h1 += h4;
    h2 += h1; h3 += h1; h4 += h1;

    out[0] = h1;
    out[1] = h2;
    out[2] = h3;
    out[3] = h4;
}

static inline void _murmur128x64_process(unsigned long long ph[2], unsigned long long pcarry[2], const void * const key, unsigned len)
{
    unsigned long long h1 = ph[0];
    unsigned long long h2 = ph[1];

    unsigned long long k1 = pcarry[0];
    unsigned long long k2 = pcarry[1];

    const unsigned char *ptr = (unsigned char *)key;
    const unsigned char *end;

    int n = k2 & 15;
    int i = -(intptr_t)(void *)ptr & 7;

    if(i && i <= len) {
	dobytes128x64(i, h1, h2, k1, k2, n, ptr, len);
    }

    end = ptr + (len & ~15);

    switch(n) {
	case 0:{
	    for( ; ptr < end ; ptr+=16) {
		k1 = READ_64(ptr, 0);
		k2 = READ_64(ptr, 1);
		doblock128x64(h1, h2, k1, k2);
	    }
	    break;
	}
	case 1: case 2: case 3: case 4: case 5: case 6: case 7:{
	    const int lshift = n*8, rshift = 64-lshift;
	    for( ; ptr < end ; ptr+=16) {
		unsigned long long c = k1>>rshift;
		k2 = READ_64(ptr, 0);
		c |= k2<<lshift;
		k1 = READ_64(ptr, 1);
		k2 = k2>>rshift | k1<<lshift;
		doblock128x64(h1, h2, c, k2);
	    }
	    break;
	}
	case 8:{
	    for( ; ptr < end ; ptr+=16) {
		k2 = READ_64(ptr, 0);
		doblock128x64(h1, h2, k1, k2);
		k1 = READ_64(ptr, 1);
	    }
	    break;
	}
	default: {
	    const int lshift = n*8-64, rshift = 64-lshift;
	    for( ; ptr < end ; ptr+=16) {
		unsigned long long c = k2 >> rshift;
		k2 = READ_64(ptr, 0);
		c |= k2 << lshift;
		doblock128x64(h1, h2, k1, c);
		k1 = k2 >> rshift;
		k2 = READ_64(ptr, 1);
		k1 |= k2 << lshift;
	    }
	    break;
	}
    }

    len -= len & ~15;

    dobytes128x64(len, h1, h2, k1, k2, n, ptr, len);

    ph[0] = h1;
    ph[1] = h2;
    pcarry[0] = k1;
    pcarry[1] = (k2 & ~0xff) | n;
}

static inline void _murmur128x86_process(unsigned ph[4], unsigned pcarry[4], const void * const key, unsigned len)
{
    unsigned h1 = ph[0];
    unsigned h2 = ph[1];
    unsigned h3 = ph[2];
    unsigned h4 = ph[3];

    unsigned k1 = pcarry[0];
    unsigned k2 = pcarry[1];
    unsigned k3 = pcarry[2];
    unsigned k4 = pcarry[3];

    const unsigned char *ptr = (unsigned char *)key;
    const unsigned char *end;

    int n = k4 & 15;
    int i = -(intptr_t)(void *)ptr & 3;

    if(i && i <= len) {
	dobytes128x86(i, h1, h2, h3, h4, k1, k2, k3, k4, n, ptr, len);
    }

    end = ptr + (len & ~15);

    switch(n) {
	case 0:
	    for( ; ptr < end ; ptr+=16) {
		k1 = READ_32(ptr, 0);
		k2 = READ_32(ptr, 1);
		k3 = READ_32(ptr, 2);
		k4 = READ_32(ptr, 3);
		doblock128x86(h1, h2, h3, h4, k1, k2, k3, k4);
	    }
	    break;
	case 1: case 2: case 3: {
	    const int lshift = n*8, rshift = 32-lshift;
	    for( ; ptr < end ; ptr+=16) {
		unsigned c = k1>>rshift;
		k2 = READ_32(ptr, 0);
		c |= k2<<lshift;
		k1 = READ_32(ptr, 1);
		k2 = k1<<lshift | k2>>rshift;
		k4 = READ_32(ptr, 2);
		k3 = k4<<lshift | k1>>rshift;
		k1 = READ_32(ptr, 3);
		k4 = k1<<lshift | k4>>rshift;
		doblock128x86(h1, h2, h3, h4, c, k2, k3, k4);
	    }
	    break;
	}
	case 4: {
	    for( ; ptr < end ; ptr+=16) {
		k2 = READ_32(ptr, 0);
		k3 = READ_32(ptr, 1);
		k4 = READ_32(ptr, 2);
		doblock128x86(h1, h2, h3, h4, k1, k2, k3, k4);
		k1 = READ_32(ptr, 3);
	    }
	    break;
	}
	case 5: case 6: case 7: {
	    const int lshift = n*8-32, rshift = 32-lshift;
	    for( ; ptr < end ; ptr+=16) {
		unsigned c = k2>>rshift;
		k3 = READ_32(ptr, 0);
		c |= k3<<lshift;
		k4 = READ_32(ptr, 1);
		k3 = k4<<lshift | k3>>rshift;
		k2 = READ_32(ptr, 2);
		k4 = k2<<lshift | k4>>rshift;
		doblock128x86(h1, h2, h3, h4, k1, c, k3, k4);
		k1 = k2>>rshift;
		k2 = READ_32(ptr, 3);
		k1 |= k2<<lshift;
	    }
	    break;
	}
	case 8:{
	    for( ; ptr < end ; ptr+=16) {
		k3 = READ_32(ptr, 0);
		k4 = READ_32(ptr, 1);
		doblock128x86(h1, h2, h3, h4, k1, k2, k3, k4);
		k1 = READ_32(ptr, 2);
		k2 = READ_32(ptr, 3);
	    }
	    break;
	}
	case 9: case 10: case 11: {
	    const int lshift = n*8-64, rshift = 32-lshift;
	    for( ; ptr < end ; ptr+=16) {
		unsigned c = k3>>rshift;
		k4 = READ_32(ptr, 0);
		c |= k4<<lshift;
		k3 = READ_32(ptr, 1);
		k4 = k3<<lshift | k4>>rshift;
		doblock128x86(h1, h2, h3, h4, k1, k2, c, k4);
		k2 = READ_32(ptr, 2);
		k1 = k2<<lshift | k3>>rshift;
		k3 = READ_32(ptr, 3);
		k2 = k3<<lshift | k2>>rshift;
	    }
	    break;
	}
	case 12: {
	    for( ; ptr < end ; ptr+=16) {
		k4 = READ_32(ptr, 0);
		doblock128x86(h1, h2, h3, h4, k1, k2, k3, k4);
		k1 = READ_32(ptr, 1);
		k2 = READ_32(ptr, 2);
		k3 = READ_32(ptr, 3);
	    }
	    break;
	}
	default: {
	    const int lshift = n*8-96, rshift = 32-lshift;
	    for( ; ptr < end ; ptr+=16) {
		unsigned c = k4>>rshift;
		k4 = READ_32(ptr, 0);
		c |= k4<<lshift;
		doblock128x86(h1, h2, h3, h4, k1, k2, k3, c);
		k3 = READ_32(ptr, 1);
		k1 = k3<<lshift | k4>>rshift;
		c  = READ_32(ptr, 2);
		k2 = c<<lshift | k3>>rshift;
		k4 = READ_32(ptr, 3);
		k3 = k4<<lshift | c>>rshift;
	    }
	    break;
	}
    }

    len -= len & ~15;

    dobytes128x86(len, h1, h2, h3, h4, k1, k2, k3, k4, n, ptr, len);

    ph[0] = h1;
    ph[1] = h2;
    ph[2] = h3;
    ph[3] = h4;
    pcarry[0] = k1;
    pcarry[1] = k2;
    pcarry[2] = k3;
    pcarry[3] = (k4 & ~0xff) | n;
}




#pragma mark - FUNCTIONS
int murmur3a_init(hash_state *hs)
{
    hs->murmur3a.h = 0;
    hs->murmur3a.carry = 0;
    hs->murmur3a.len = 0;

    return NBSCrypto_OK;
}

int murmur3c_init(hash_state *hs)
{
    memset(&hs->murmur3c.h, 0, sizeof(hs->murmur3c.h));
    memset(&hs->murmur3c.carry, 0, sizeof(hs->murmur3c.carry));
    hs->murmur3c.len = 0;

    return NBSCrypto_OK;
}

int murmur3f_init(hash_state *hs)
{
    memset(&hs->murmur3f.h, 0, sizeof(hs->murmur3f.h));
    memset(&hs->murmur3f.carry, 0, sizeof(hs->murmur3f.carry));
    hs->murmur3f.len = 0;

    return NBSCrypto_OK;
}

int murmur3a_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    hs->murmur3a.len += inlen;
    _murmur32_process(&hs->murmur3a.h, &hs->murmur3a.carry, in, (unsigned)inlen);

    return NBSCrypto_OK;
}

int murmur3c_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    hs->murmur3c.len += inlen;
    _murmur128x86_process(hs->murmur3c.h, hs->murmur3c.carry, in, (unsigned)inlen);

    return NBSCrypto_OK;
}

int murmur3f_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    hs->murmur3f.len += inlen;
    _murmur128x64_process(hs->murmur3f.h, hs->murmur3f.carry, in, (unsigned)inlen);

    return NBSCrypto_OK;
}

int murmur3a_done(hash_state *hs, unsigned char out[4])
{
    hs->murmur3a.h = _murmur32_result(hs->murmur3a.h, hs->murmur3a.carry, hs->murmur3a.len);

    out[0] = (unsigned char)((hs->murmur3a.h >> 24) & 0xff);
    out[1] = (unsigned char)((hs->murmur3a.h >> 16) & 0xff);
    out[2] = (unsigned char)((hs->murmur3a.h >>  8) & 0xff);
    out[3] = (unsigned char) (hs->murmur3a.h & 0xff);

    return NBSCrypto_OK;
}

int murmur3c_done(hash_state *hs, unsigned char out[16])
{
    unsigned h[4] = {0, 0, 0, 0};
    _murmur128x86_result(hs->murmur3c.h, hs->murmur3c.carry, hs->murmur3c.len, h);

    out[ 0] = (unsigned char)((h[0] >> 24) & 0xff);
    out[ 1] = (unsigned char)((h[0] >> 16) & 0xff);
    out[ 2] = (unsigned char)((h[0] >>  8) & 0xff);
    out[ 3] = (unsigned char)( h[0] & 0xff);
    out[ 4] = (unsigned char)((h[1] >> 24) & 0xff);
    out[ 5] = (unsigned char)((h[1] >> 16) & 0xff);
    out[ 6] = (unsigned char)((h[1] >>  8) & 0xff);
    out[ 7] = (unsigned char)( h[1] & 0xff);
    out[ 8] = (unsigned char)((h[2] >> 24) & 0xff);
    out[ 9] = (unsigned char)((h[2] >> 16) & 0xff);
    out[10] = (unsigned char)((h[2] >>  8) & 0xff);
    out[11] = (unsigned char)( h[2] & 0xff);
    out[12] = (unsigned char)((h[3] >> 24) & 0xff);
    out[13] = (unsigned char)((h[3] >> 16) & 0xff);
    out[14] = (unsigned char)((h[3] >>  8) & 0xff);
    out[15] = (unsigned char)( h[3] & 0xff);

    return NBSCrypto_OK;
}

int murmur3f_done(hash_state *hs, unsigned char out[16])
{
    uint64_t h[2] = {0, 0};
    _murmur128x64_result(hs->murmur3f.h, hs->murmur3f.carry, hs->murmur3f.len, h);

    out[ 0] = (unsigned char)((h[0] >> 56) & 0xff);
    out[ 1] = (unsigned char)((h[0] >> 48) & 0xff);
    out[ 2] = (unsigned char)((h[0] >> 40) & 0xff);
    out[ 3] = (unsigned char)((h[0] >> 32) & 0xff);
    out[ 4] = (unsigned char)((h[0] >> 24) & 0xff);
    out[ 5] = (unsigned char)((h[0] >> 16) & 0xff);
    out[ 6] = (unsigned char)((h[0] >>  8) & 0xff);
    out[ 7] = (unsigned char)( h[0] & 0xff);
    out[ 8] = (unsigned char)((h[1] >> 56) & 0xff);
    out[ 9] = (unsigned char)((h[1] >> 48) & 0xff);
    out[10] = (unsigned char)((h[1] >> 40) & 0xff);
    out[11] = (unsigned char)((h[1] >> 32) & 0xff);
    out[12] = (unsigned char)((h[1] >> 24) & 0xff);
    out[13] = (unsigned char)((h[1] >> 16) & 0xff);
    out[14] = (unsigned char)((h[1] >>  8) & 0xff);
    out[15] = (unsigned char)(h[1] & 0xff);

    return NBSCrypto_OK;
}
