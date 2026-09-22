//
//	rc5.c
//	Authors / Developers		: Ronald L. Rivest
//	Last Modified (Original)	: 1994
//


#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor rc5_desc =
{
    "rc5",
    26,
    1, 128, 8, 12,
    &rc5_setup,
    &rc5_encrypt,
    &rc5_decrypt,
    &rc5_done,
};




#pragma mark - DEFINES

#define BSWAP(x)  ( ((x>>24)&0x000000FFUL) | ((x<<24)&0xFF000000UL) | ((x>>8)&0x0000FF00UL) | ((x<<8)&0x00FF0000UL) )
#define ROL(x, y) ( (((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFFUL)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFFUL)
#define ROLc(x, y)( (((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFFUL)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFFUL)
#define ROR(x, y) ( ((((unsigned)(x)&0xFFFFFFFFUL)>>(unsigned)((y)&31)) | ((unsigned)(x)<<(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFFUL)

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define LOAD32L(x, y)				\
    do {x = ((unsigned)((y)[3] & 255)<<24) |	\
	    ((unsigned)((y)[2] & 255)<<16) |	\
	    ((unsigned)((y)[1] & 255)<< 8) |	\
	    ((unsigned)((y)[0] & 255)); }	\
    while(0)

#define STORE32L(x, y)				\
    do {(y)[3] = (unsigned char)(((x)>>24)&255);\
	(y)[2] = (unsigned char)(((x)>>16)&255);\
	(y)[1] = (unsigned char)(((x)>> 8)&255);\
	(y)[0] = (unsigned char)((x)&255); }	\
    while(0)

static const unsigned stab[50] = {
    0xb7e15163UL, 0x5618cb1cUL, 0xf45044d5UL, 0x9287be8eUL, 0x30bf3847UL,
    0xcef6b200UL, 0x6d2e2bb9UL, 0x0b65a572UL, 0xa99d1f2bUL, 0x47d498e4UL,
    0xe60c129dUL, 0x84438c56UL, 0x227b060fUL, 0xc0b27fc8UL, 0x5ee9f981UL,
    0xfd21733aUL, 0x9b58ecf3UL, 0x399066acUL, 0xd7c7e065UL, 0x75ff5a1eUL,
    0x1436d3d7UL, 0xb26e4d90UL, 0x50a5c749UL, 0xeedd4102UL, 0x8d14babbUL,
    0x2b4c3474UL, 0xc983ae2dUL, 0x67bb27e6UL, 0x05f2a19fUL, 0xa42a1b58UL,
    0x42619511UL, 0xe0990ecaUL, 0x7ed08883UL, 0x1d08023cUL, 0xbb3f7bf5UL,
    0x5976f5aeUL, 0xf7ae6f67UL, 0x95e5e920UL, 0x341d62d9UL, 0xd254dc92UL,
    0x708c564bUL, 0x0ec3d004UL, 0xacfb49bdUL, 0x4b32c376UL, 0xe96a3d2fUL,
    0x87a1b6e8UL, 0x25d930a1UL, 0xc410aa5aUL, 0x62482413UL, 0x007f9dccUL
};




#pragma mark - FUNCTIONS
int rc5_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    unsigned L[64], *S, A, B, i, j, v, s, t, l;

    if (num_rounds == 0) {
	num_rounds = rc5_desc.default_rounds;
    }

    if (num_rounds < 12 || num_rounds > 24) {
	return NBSCrypto_ERROR;
    }

    if (keylen < 8 || keylen > 128) {
	return NBSCrypto_ERROR;
    }

    cs->rc5.rounds = num_rounds;
    S = cs->rc5.K;

    for (A = i = j = 0; i < (unsigned)keylen; ) {
	A = (A << 8) | ((unsigned)(key[i++] & 255));
	if ((i & 3) == 0) {
	    L[j++] = BSWAP(A);
	    A = 0;
	}
    }

    if ((keylen & 3) != 0) {
	A <<= (unsigned)((8 * (4 - (keylen&3))));
	L[j++] = BSWAP(A);
    }

    t = (unsigned)(2 * (num_rounds + 1));
    memcpy(S, stab, t * sizeof(*S));

    s = 3 * MAX(t, j);
    l = j;
    for (A = B = i = j = v = 0; v < s; v++) {
	A = S[i] = ROLc(S[i] + A + B, 3);
	B = L[j] = ROL(L[j] + A + B, (A+B));
	if (++i == t) { i = 0; }
	if (++j == l) { j = 0; }
    }

    return NBSCrypto_OK;
}

int rc5_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    int r;
    unsigned A, B;
    const unsigned *K;

    if (cs->rc5.rounds < 12 || cs->rc5.rounds > 24) {
	return NBSCrypto_ERROR;
    }

    LOAD32L(A, &pt[0]);
    LOAD32L(B, &pt[4]);
    A += cs->rc5.K[0];
    B += cs->rc5.K[1];
    K  = cs->rc5.K + 2;

    if ((cs->rc5.rounds & 1) == 0) {
	for (r = 0; r < cs->rc5.rounds; r += 2) {
	    A = ROL(A ^ B, B) + K[0];
	    B = ROL(B ^ A, A) + K[1];
	    A = ROL(A ^ B, B) + K[2];
	    B = ROL(B ^ A, A) + K[3];
	    K += 4;
	}
    } else {
	for (r = 0; r < cs->rc5.rounds; r++) {
	    A = ROL(A ^ B, B) + K[0];
	    B = ROL(B ^ A, A) + K[1];
	    K += 2;
	}
    }
    STORE32L(A, &ct[0]);
    STORE32L(B, &ct[4]);

    return NBSCrypto_OK;
}

int rc5_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    int r;
    unsigned A, B;
    const unsigned *K;

    if (cs->rc5.rounds < 12 || cs->rc5.rounds > 24) {
	return NBSCrypto_ERROR;
    }

    LOAD32L(A, &ct[0]);
    LOAD32L(B, &ct[4]);
    K = cs->rc5.K + (cs->rc5.rounds << 1);

    if ((cs->rc5.rounds & 1) == 0) {
	K -= 2;
	for (r = cs->rc5.rounds - 1; r >= 0; r -= 2) {
	    B = ROR(B - K[3], A) ^ A;
	    A = ROR(A - K[2], B) ^ B;
	    B = ROR(B - K[1], A) ^ A;
	    A = ROR(A - K[0], B) ^ B;
	    K -= 4;
	}
    } else {
	for (r = cs->rc5.rounds - 1; r >= 0; r--) {
	    B = ROR(B - K[1], A) ^ A;
	    A = ROR(A - K[0], B) ^ B;
	    K -= 2;
	}
    }
    A -= cs->rc5.K[0];
    B -= cs->rc5.K[1];
    STORE32L(A, &pt[0]);
    STORE32L(B, &pt[4]);

    return NBSCrypto_OK;
}

void rc5_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->rc5));
}
