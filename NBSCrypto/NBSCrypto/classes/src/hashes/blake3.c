//
//	blake3.c
//	Authors / Developers		: Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, Zooko Wilcox-O'Hearn
//	Last Modified (Original)	: 2020
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor blake3_desc =
{
    "blake3",
    14,
    32,
    64,
    &blake3_init,
    &blake3_process,
    &blake3_done,
    NULL
};




#pragma mark - DEFINES

#define CHUNK_START (1u << 0)
#define CHUNK_END   (1u << 1)
#define PARENT      (1u << 2)
#define ROOT        (1u << 3)

#define G(i, j, a, b, c, d)		\
    a = a + b + m[s[i][j * 2]];		\
    d = d ^ a;				\
    d = d >> 16 | d << 16;		\
    c = c + d;				\
    b = b ^ c;				\
    b = b >> 12 | b << 20;		\
    a = a + b + m[s[i][j * 2 + 1]];	\
    d = d ^ a;				\
    d = d >> 8 | d << 24;		\
    c = c + d;				\
    b = b ^ c;				\
    b = b >> 7 | b << 25;

#define ROUND(i)			\
    G(i, 0, v[0], v[4], v[ 8], v[12])	\
    G(i, 1, v[1], v[5], v[ 9], v[13])	\
    G(i, 2, v[2], v[6], v[10], v[14])	\
    G(i, 3, v[3], v[7], v[11], v[15])	\
    G(i, 4, v[0], v[5], v[10], v[15])	\
    G(i, 5, v[1], v[6], v[11], v[12])	\
    G(i, 6, v[2], v[7], v[ 8], v[13])	\
    G(i, 7, v[3], v[4], v[ 9], v[14])

static const unsigned int iv[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static const unsigned char s[][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    { 2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8},
    { 3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1},
    {10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6},
    {12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4},
    { 9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7},
    {11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13},
};




#pragma mark - INLINE
static inline void _compress(unsigned int *out, const unsigned int m[static 16], const unsigned int h[static 8], unsigned long long t, unsigned int b, unsigned int d)
{
    unsigned i;

    unsigned int v[16] = {
	h[0], h[1], h[2], h[3],
	h[4], h[5], h[6], h[7],
	iv[0], iv[1], iv[2], iv[3],
	(unsigned int)t, t >> 32, b, d,
    };

    ROUND(0) ROUND(1) ROUND(2) ROUND(3) ROUND(4) ROUND(5) ROUND(6)

    if (d & ROOT) {
	for (i = 8; i < 16; ++i){
	    out[i] = v[i] ^ h[i - 8];
	}
    }
    for (i = 0; i < 8; ++i){
	out[i] = v[i] ^ v[i + 8];
    }
}

static inline void _load(unsigned int d[static 16], const unsigned char s[static 64])
{
    unsigned int *end;

    for (end = d + 16; d < end; ++d, s += 4){
	*d = (unsigned int)s[0] | (unsigned int)s[1] <<  8 | (unsigned int)s[2] << 16 | (unsigned int)s[3] << 24;
    }
}

static inline void _block(hash_state *hs, const unsigned char *in)
{
    unsigned int m[16], flags, *cv = hs->blake3.cv;
    unsigned long long t;

    flags = 0;
    switch (hs->blake3.block) {
	case 0:  flags |= CHUNK_START; break;
	case 15: flags |= CHUNK_END;   break;
    }
    _load(m, in);
    _compress(cv, m, cv, hs->blake3.chunk, 64, flags);
    if (++hs->blake3.block == 16) {
	hs->blake3.block = 0;
	for (t = ++hs->blake3.chunk; (t & 1) == 0; t >>= 1) {
	    cv -= 8;
	    _compress(cv, cv, iv, 0, 64, PARENT);
	}
	cv += 8;
	memcpy(cv, iv, sizeof(iv));
    }
    hs->blake3.cv = cv;
}




#pragma mark - FUNCTIONS

int blake3_init(hash_state *hs)
{
    hs->blake3.bytes = 0;
    hs->blake3.block = 0;
    hs->blake3.chunk = 0;
    hs->blake3.cv = hs->blake3.cv_buf;
    memcpy(hs->blake3.cv, iv, sizeof(iv));

    return NBSCrypto_OK;
}

int blake3_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    size_t n;
    const unsigned char *pos = in;

    if (hs->blake3.bytes){
	n = 64 - hs->blake3.bytes;
	if (inlen < n){
	    n = inlen;
	}
	memcpy(hs->blake3.input + hs->blake3.bytes, pos, n);
	pos += n;
	inlen -= n;
	hs->blake3.bytes += n;
	if (!inlen){
	    return NBSCrypto_ERROR;
	}
	_block(hs, hs->blake3.input);
    }
    for (; inlen > 64; pos += 64, inlen -= 64){
	_block(hs, pos);
    }
    hs->blake3.bytes = (int)inlen;
    memcpy(hs->blake3.input, pos, inlen);

    return NBSCrypto_OK;
}

int blake3_done(hash_state *hs, unsigned char *out)
{
    size_t i;
    size_t len = 32;
    unsigned int flags, b, x=0, *in, *cv, m[16], root[16];

    cv = hs->blake3.cv;
    memset(hs->blake3.input + hs->blake3.bytes, 0, 64 - hs->blake3.bytes);
    _load(m, hs->blake3.input);
    flags = CHUNK_END;
    if(hs->blake3.block == 0){
	flags |= CHUNK_START;
    }
    if(cv == hs->blake3.cv_buf){
	b = hs->blake3.bytes;
	in = m;
    }else{
	_compress(cv, m, cv, hs->blake3.chunk, hs->blake3.bytes, flags);
	flags = PARENT;
	while ((cv -= 8) != hs->blake3.cv_buf){
	    _compress(cv, cv, iv, 0, 64, flags);
	}
	b = 64;
	in = cv;
	cv = (unsigned int *)iv;
    }
    flags |= ROOT;
    for(i = 0; i < len; ++i, ++out, x >>= 8){
	if((i & 63) == 0){
	    _compress(root, in, cv, i >> 6, b, flags);
	}
	if((i & 3) == 0){
	    x = root[i >> 2 & 15];
	}
	*out = x & 0xff;
    }

    return NBSCrypto_OK;
}
