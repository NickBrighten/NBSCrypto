//
//	blake2b.c
//	Authors / Developers		: Jean-Philippe Aumasson, Luca Henzen, Willi Meier, Raphael C.-W. Phan
//	Last Modified (Original)	: October 9, 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor blake2b_160_desc =
{
    "blake2b-160",
    6,
    20,
    128,
    &blake2b_160_init,
    &blake2b_process,
    &blake2b_done,
    NULL
};

const struct hash_descriptor blake2b_256_desc =
{
    "blake2b-256",
    7,
    32,
    128,
    &blake2b_256_init,
    &blake2b_process,
    &blake2b_done,
    NULL
};

const struct hash_descriptor blake2b_384_desc =
{
    "blake2b-384",
    8,
    48,
    128,
    &blake2b_384_init,
    &blake2b_process,
    &blake2b_done,
    NULL
};

const struct hash_descriptor blake2b_512_desc =
{
    "blake2b-512",
    9,
    64,
    128,
    &blake2b_512_init,
    &blake2b_process,
    &blake2b_done,
    NULL
};




#pragma mark - DEFINES
#define G(r, i, a, b, c, d) do {		\
    a = a + b + m[BLAKE2B_SIGMA[r][2 * i + 0]];	\
    d = ROR64(d ^ a, 32);			\
    c = c + d;					\
    b = ROR64(b ^ c, 24);			\
    a = a + b + m[BLAKE2B_SIGMA[r][2 * i + 1]];	\
    d = ROR64(d ^ a, 16);			\
    c = c + d;					\
    b = ROR64(b ^ c, 63);			\
} while (0)

#define ROUND(r) do {			\
    G(r, 0, v[0], v[4], v[8], v[12]);	\
    G(r, 1, v[1], v[5], v[9], v[13]);	\
    G(r, 2, v[2], v[6], v[10], v[14]);	\
    G(r, 3, v[3], v[7], v[11], v[15]);	\
    G(r, 4, v[0], v[5], v[10], v[15]);	\
    G(r, 5, v[1], v[6], v[11], v[12]);	\
    G(r, 6, v[2], v[7], v[8], v[13]);	\
    G(r, 7, v[3], v[4], v[9], v[14]);	\
} while (0)

#define STORE64L(x,y) do {								\
    (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);	\
    (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);	\
    (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);	\
    (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD64L(x, y) do {				\
    x = (((unsigned long long)((y)[7] & 255))<<56)|	\
	(((unsigned long long)((y)[6] & 255))<<48)|	\
	(((unsigned long long)((y)[5] & 255))<<40)|	\
	(((unsigned long long)((y)[4] & 255))<<32)|	\
	(((unsigned long long)((y)[3] & 255))<<24)|	\
	(((unsigned long long)((y)[2] & 255))<<16)|	\
	(((unsigned long long)((y)[1] & 255))<<8)|	\
	(((unsigned long long)((y)[0] & 255)));		\
} while(0)

#define ROR64(x, y) (((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((unsigned long long)(y)&CONST64(63))) | ((x)<<(((unsigned long long)64-((y)&63))&63))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define CONST64(n) n ## ULL


enum blake2b_constant {
    BLAKE2B_BLOCKBYTES		= 128,
    BLAKE2B_OUTBYTES		= 64,
    BLAKE2B_KEYBYTES		= 64,
    BLAKE2B_SALTBYTES		= 16,
    BLAKE2B_PERSONALBYTES	= 16,
    BLAKE2B_PARAM_SIZE		= 64
};

enum {
    O_DIGEST_LENGTH		= 0,
    O_KEY_LENGTH		= 1,
    O_FANOUT			= 2,
    O_DEPTH			= 3,
    O_LEAF_LENGTH		= 4,
    O_NODE_OFFSET		= 8,
    O_XOF_LENGTH		= 12,
    O_NODE_DEPTH		= 16,
    O_INNER_LENGTH		= 17,
    O_RESERVED			= 18,
    O_SALT			= 32,
    O_PERSONAL			= 48
};

static const unsigned long long BLAKE2B_IV[8] =
{
    CONST64(0x6a09e667f3bcc908), CONST64(0xbb67ae8584caa73b), CONST64(0x3c6ef372fe94f82b), CONST64(0xa54ff53a5f1d36f1),
    CONST64(0x510e527fade682d1), CONST64(0x9b05688c2b3e6c1f), CONST64(0x1f83d9abfb41bd6b), CONST64(0x5be0cd19137e2179)
};

static const unsigned char BLAKE2B_SIGMA[12][16] =
{
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};




#pragma mark - INLINE
static inline void _blake2b_set_lastnode(hash_state *hs) {hs->blake2b.f[1]=CONST64(0xffffffffffffffff);}
static inline int _blake2b_is_lastblock(const hash_state *hs) {return hs->blake2b.f[0]!=0;}

static inline void _blake2b_set_lastblock(hash_state *hs)
{
    if (hs->blake2b.last_node) {
	_blake2b_set_lastnode(hs);
    }
    hs->blake2b.f[0] = CONST64(0xffffffffffffffff);
}

static inline void _blake2b_increment_counter(hash_state *hs, unsigned long long inc)
{
    hs->blake2b.t[0] += inc;
    if (hs->blake2b.t[0] < inc) hs->blake2b.t[1]++;
}

static inline int _blake2b_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned long long m[16];
    unsigned long long v[16];
    unsigned long i;

    for (i = 0; i < 16; ++i) {
	LOAD64L(m[i], buf + i * sizeof(m[i]));
    }

    for (i = 0; i < 8; ++i) {
	v[i] = hs->blake2b.h[i];
    }

    v[8]  = BLAKE2B_IV[0];
    v[9]  = BLAKE2B_IV[1];
    v[10] = BLAKE2B_IV[2];
    v[11] = BLAKE2B_IV[3];
    v[12] = BLAKE2B_IV[4] ^ hs->blake2b.t[0];
    v[13] = BLAKE2B_IV[5] ^ hs->blake2b.t[1];
    v[14] = BLAKE2B_IV[6] ^ hs->blake2b.f[0];
    v[15] = BLAKE2B_IV[7] ^ hs->blake2b.f[1];

    ROUND(0);
    ROUND(1);
    ROUND(2);
    ROUND(3);
    ROUND(4);
    ROUND(5);
    ROUND(6);
    ROUND(7);
    ROUND(8);
    ROUND(9);
    ROUND(10);
    ROUND(11);

    for (i = 0; i < 8; ++i) {
	hs->blake2b.h[i] = hs->blake2b.h[i] ^ v[i] ^ v[i + 8];
    }

    return NBSCrypto_OK;
}

static inline void _blake2b_init0(hash_state *hs)
{
    unsigned long i;
    memset(&hs->blake2b, 0, sizeof(hs->blake2b));

    for (i = 0; i < 8; ++i) {
	hs->blake2b.h[i] = BLAKE2B_IV[i];
    }
}

static inline int _blake2b_init_param(hash_state *hs, const unsigned char *P)
{
    unsigned long i;

    _blake2b_init0(hs);

    for (i = 0; i < 8; ++i) {
	unsigned long long tmp;
	LOAD64L(tmp, P + i * 8);
	hs->blake2b.h[i] ^= tmp;
    }

    hs->blake2b.outlen = P[O_DIGEST_LENGTH];

    return NBSCrypto_OK;
}

static inline int _blake2b_init(hash_state *hs, unsigned long outlen, const unsigned char *key, unsigned long keylen)
{
    unsigned char P[BLAKE2B_PARAM_SIZE];
    int err;

    if ((!outlen) || (outlen > BLAKE2B_OUTBYTES)) {
	return NBSCrypto_ERROR;
    }
    if ((key && !keylen) || (keylen && !key) || (keylen > BLAKE2B_KEYBYTES)) {
	return NBSCrypto_ERROR;
    }

    memset(P, 0, sizeof(P));

    P[O_DIGEST_LENGTH] = (unsigned char)outlen;
    P[O_KEY_LENGTH] = (unsigned char)keylen;
    P[O_FANOUT] = 1;
    P[O_DEPTH] = 1;

    err = _blake2b_init_param(hs, P);
    if (err != NBSCrypto_OK) return err;

    if (key) {
	unsigned char block[BLAKE2B_BLOCKBYTES];

	memset(block, 0, BLAKE2B_BLOCKBYTES);
	memcpy(block, key, keylen);
	blake2b_process(hs, block, BLAKE2B_BLOCKBYTES);
    }

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int blake2b_160_init(hash_state *hs) { return _blake2b_init(hs, 20, NULL, 0); }
int blake2b_256_init(hash_state *hs) { return _blake2b_init(hs, 32, NULL, 0); }
int blake2b_384_init(hash_state *hs) { return _blake2b_init(hs, 48, NULL, 0); }
int blake2b_512_init(hash_state *hs) { return _blake2b_init(hs, 64, NULL, 0); }

int blake2b_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    if (hs->blake2b.curlen > sizeof(hs->blake2b.buf)) {
	return NBSCrypto_ERROR;
    }

    if (inlen > 0) {
	unsigned long left = hs->blake2b.curlen;
	unsigned long fill = BLAKE2B_BLOCKBYTES - left;
	if (inlen > fill) {
	    hs->blake2b.curlen = 0;
	    memcpy(hs->blake2b.buf + (left % sizeof(hs->blake2b.buf)), in, fill);
	    _blake2b_increment_counter(hs, BLAKE2B_BLOCKBYTES);
	    _blake2b_compress(hs, hs->blake2b.buf);
	    in += fill;
	    inlen -= fill;
	    while (inlen > BLAKE2B_BLOCKBYTES) {
		_blake2b_increment_counter(hs, BLAKE2B_BLOCKBYTES);
		_blake2b_compress(hs, in);
		in += BLAKE2B_BLOCKBYTES;
		inlen -= BLAKE2B_BLOCKBYTES;
	    }
	}
	memcpy(hs->blake2b.buf + hs->blake2b.curlen, in, inlen);
	hs->blake2b.curlen += inlen;
    }

    return NBSCrypto_OK;
}

int blake2b_done(hash_state *hs, unsigned char *out)
{
    unsigned char buffer[BLAKE2B_OUTBYTES] = { 0 };
    unsigned long i;

    if (_blake2b_is_lastblock(hs)) {
	return NBSCrypto_ERROR;
    }

    _blake2b_increment_counter(hs, hs->blake2b.curlen);
    _blake2b_set_lastblock(hs);
    memset(hs->blake2b.buf + hs->blake2b.curlen, 0, BLAKE2B_BLOCKBYTES - hs->blake2b.curlen);
    _blake2b_compress(hs, hs->blake2b.buf);

    for (i = 0; i < 8; ++i) {
	STORE64L(hs->blake2b.h[i], buffer + i * 8);
    }

    memcpy(out, buffer, hs->blake2b.outlen);
    zeromem(hs, sizeof(hash_state));

    return NBSCrypto_OK;
}
