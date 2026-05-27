//
//	blake2s.c
//	Authors / Developers		: Jean-Philippe Aumasson, Luca Henzen, Willi Meier, Raphael C.-W. Phan
//	Last Modified (Original)	: October 9, 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor blake2s_128_desc =
{
    "blake2s-128",
    10,
    16,
    64,
    &blake2s_128_init,
    &blake2s_process,
    &blake2s_done,
    NULL
};

const struct hash_descriptor blake2s_160_desc =
{
    "blake2s-160",
    11,
    20,
    64,
    &blake2s_160_init,
    &blake2s_process,
    &blake2s_done,
    NULL
};

const struct hash_descriptor blake2s_224_desc =
{
    "blake2s-224",
    12,
    28,
    64,
    &blake2s_224_init,
    &blake2s_process,
    &blake2s_done,
    NULL
};

const struct hash_descriptor blake2s_256_desc =
{
    "blake2s-256",
    13,
    32,
    64,
    &blake2s_256_init,
    &blake2s_process,
    &blake2s_done,
    NULL
};




#pragma mark - DEFINES
#define G(r, i, a, b, c, d) do {		\
a = a + b + m[BLAKE2S_SIGMA[r][2 * i + 0]];	\
d = ROR(d ^ a, 16);				\
c = c + d;					\
b = ROR(b ^ c, 12);				\
a = a + b + m[BLAKE2S_SIGMA[r][2 * i + 1]];	\
d = ROR(d ^ a, 8);				\
c = c + d;					\
b = ROR(b ^ c, 7);				\
} while (0)

#define ROUND(r) do {				\
G(r, 0, v[ 0], v[ 4], v[ 8], v[12]);	\
G(r, 1, v[ 1], v[ 5], v[ 9], v[13]);	\
G(r, 2, v[ 2], v[ 6], v[10], v[14]);	\
G(r, 3, v[ 3], v[ 7], v[11], v[15]);	\
G(r, 4, v[ 0], v[ 5], v[10], v[15]);	\
G(r, 5, v[ 1], v[ 6], v[11], v[12]);	\
G(r, 6, v[ 2], v[ 7], v[ 8], v[13]);	\
G(r, 7, v[ 3], v[ 4], v[ 9], v[14]);	\
} while (0)

#define STORE32L(x, y) do {								\
(y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);	\
(y)[1] = (unsigned char)(((x)>> 8)&255); (y)[0] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD32L(x, y) do {							\
x = ((unsigned)((y)[3] & 255)<<24) | ((unsigned)((y)[2] & 255)<<16) |	\
((unsigned)((y)[1] & 255)<< 8) | ((unsigned)((y)[0] & 255));		\
} while(0)

#define ROR(x, y) (((((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((y)&31)) | ((unsigned)(x)<<(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)


enum blake2s_constant {
    BLAKE2S_BLOCKBYTES		= 64,
    BLAKE2S_OUTBYTES		= 32,
    BLAKE2S_KEYBYTES		= 32,
    BLAKE2S_SALTBYTES		= 8,
    BLAKE2S_PERSONALBYTES	= 8,
    BLAKE2S_PARAM_SIZE		= 32
};

enum {
    O_DIGEST_LENGTH		= 0,
    O_KEY_LENGTH		= 1,
    O_FANOUT			= 2,
    O_DEPTH			= 3,
    O_LEAF_LENGTH		= 4,
    O_NODE_OFFSET		= 8,
    O_XOF_LENGTH		= 12,
    O_NODE_DEPTH		= 14,
    O_INNER_LENGTH		= 15,
    O_SALT			= 16,
    O_PERSONAL			= 24
};

static const unsigned BLAKE2S_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const unsigned char BLAKE2S_SIGMA[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};




#pragma mark - INLINE

static inline void _blake2s_set_lastnode(hash_state *hs) {hs->blake2s.f[1]=0xffffffffUL;}
static inline int _blake2s_is_lastblock(const hash_state *hs) {return hs->blake2s.f[0]!=0;}

static inline void _blake2s_set_lastblock(hash_state *hs)
{
    if (hs->blake2s.last_node) {
	_blake2s_set_lastnode(hs);
    }
    hs->blake2s.f[0] = 0xffffffffUL;
}

static inline void _blake2s_increment_counter(hash_state *hs, unsigned long inc)
{
    hs->blake2s.t[0] += inc;
    if (hs->blake2s.t[0] < inc) hs->blake2s.t[1]++;
}

static inline int _blake2s_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned long i;
    unsigned m[16];
    unsigned v[16];

    for (i = 0; i < 16; ++i) {
	LOAD32L(m[i], buf + i * sizeof(m[i]));
    }

    for (i = 0; i < 8; ++i) {
	v[i] = hs->blake2s.h[i];
    }

    v[8]  = BLAKE2S_IV[0];
    v[9]  = BLAKE2S_IV[1];
    v[10] = BLAKE2S_IV[2];
    v[11] = BLAKE2S_IV[3];
    v[12] = hs->blake2s.t[0] ^ BLAKE2S_IV[4];
    v[13] = hs->blake2s.t[1] ^ BLAKE2S_IV[5];
    v[14] = hs->blake2s.f[0] ^ BLAKE2S_IV[6];
    v[15] = hs->blake2s.f[1] ^ BLAKE2S_IV[7];

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

    for (i = 0; i < 8; ++i) {
	hs->blake2s.h[i] = hs->blake2s.h[i] ^ v[i] ^ v[i + 8];
    }

    return NBSCrypto_OK;
}

static inline int _blake2s_init0(hash_state *hs)
{
    int i;
    memset(&hs->blake2s, 0, sizeof(struct blake2s_state));

    for (i = 0; i < 8; ++i) {
	hs->blake2s.h[i] = BLAKE2S_IV[i];
    }

    return NBSCrypto_OK;
}

static inline int _blake2s_init_param(hash_state *hs, const unsigned char *P)
{
    unsigned long i;

    _blake2s_init0(hs);

    for (i = 0; i < 8; ++i) {
	unsigned tmp;
	LOAD32L(tmp, P + i * 4);
	hs->blake2s.h[i] ^= tmp;
    }

    hs->blake2s.outlen = P[O_DIGEST_LENGTH];

    return NBSCrypto_OK;
}

static inline int _blake2s_init(hash_state *hs, unsigned long outlen, const unsigned char *key, unsigned long keylen)
{
    unsigned char P[BLAKE2S_PARAM_SIZE];
    int err;

    if ((!outlen) || (outlen > BLAKE2S_OUTBYTES)) {
	return NBSCrypto_ERROR;
    }
    if ((key && !keylen) || (keylen && !key) || (keylen > BLAKE2S_KEYBYTES)) {
	return NBSCrypto_ERROR;
    }

    memset(P, 0, sizeof(P));

    P[O_DIGEST_LENGTH] = (unsigned char)outlen;
    P[O_KEY_LENGTH] = (unsigned char)keylen;
    P[O_FANOUT] = 1;
    P[O_DEPTH] = 1;

    err = _blake2s_init_param(hs, P);
    if (err != NBSCrypto_OK) return err;

    if (key) {
	unsigned char block[BLAKE2S_BLOCKBYTES];

	memset(block, 0, BLAKE2S_BLOCKBYTES);
	memcpy(block, key, keylen);
	blake2s_process(hs, block, BLAKE2S_BLOCKBYTES);
    }

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int blake2s_128_init(hash_state *hs) { return _blake2s_init(hs, 16, NULL, 0); }
int blake2s_160_init(hash_state *hs) { return _blake2s_init(hs, 20, NULL, 0); }
int blake2s_224_init(hash_state *hs) { return _blake2s_init(hs, 28, NULL, 0); }
int blake2s_256_init(hash_state *hs) { return _blake2s_init(hs, 32, NULL, 0); }

int blake2s_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    if (hs->blake2s.curlen > sizeof(hs->blake2s.buf)) {
	return NBSCrypto_ERROR;
    }

    if (inlen > 0) {
	unsigned long left = hs->blake2s.curlen;
	unsigned long fill = BLAKE2S_BLOCKBYTES - left;
	if (inlen > fill) {
	    hs->blake2s.curlen = 0;
	    memcpy(hs->blake2s.buf + (left % sizeof(hs->blake2s.buf)), in, fill);
	    _blake2s_increment_counter(hs, BLAKE2S_BLOCKBYTES);
	    _blake2s_compress(hs, hs->blake2s.buf);
	    in += fill;
	    inlen -= fill;
	    while (inlen > BLAKE2S_BLOCKBYTES) {
		_blake2s_increment_counter(hs, BLAKE2S_BLOCKBYTES);
		_blake2s_compress(hs, in);
		in += BLAKE2S_BLOCKBYTES;
		inlen -= BLAKE2S_BLOCKBYTES;
	    }
	}
	memcpy(hs->blake2s.buf + hs->blake2s.curlen, in, inlen);
	hs->blake2s.curlen += inlen;
    }

    return NBSCrypto_OK;
}

int blake2s_done(hash_state *hs, unsigned char *out)
{
    unsigned char buffer[BLAKE2S_OUTBYTES] = { 0 };
    unsigned long i;

    if (_blake2s_is_lastblock(hs)) {
	return NBSCrypto_ERROR;
    }
    _blake2s_increment_counter(hs, hs->blake2s.curlen);
    _blake2s_set_lastblock(hs);
    memset(hs->blake2s.buf + hs->blake2s.curlen, 0, BLAKE2S_BLOCKBYTES - hs->blake2s.curlen);
    _blake2s_compress(hs, hs->blake2s.buf);

    for (i = 0; i < 8; ++i) {
	STORE32L(hs->blake2s.h[i], buffer + i * 4);
    }

    memcpy(out, buffer, hs->blake2s.outlen);
    zeromem(hs, sizeof(hash_state));

    return NBSCrypto_OK;
}
