//
//	salsa.c
//	Authors / Developers		: Daniel J. Bernstein
//	Last Modified (Original)	: 2008 (2005)
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor salsa_desc =
{
    "salsa",
    32,
    16, 32, 8, 20,
    NULL,
    NULL,
    NULL,
    NULL
};




#pragma mark - DEFINES

#define MIN(x, y) (((x)<(y))?(x):(y))

#define QUARTERROUND(a,b,c,d)		\
    x[b] ^= (ROL((x[a] + x[d]),  7));	\
    x[c] ^= (ROL((x[b] + x[a]),  9));	\
    x[d] ^= (ROL((x[c] + x[b]), 13));	\
    x[a] ^= (ROL((x[d] + x[c]), 18));

#define ROL(x, y) ( (((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFFUL)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFFUL)

#define LOAD32L(x, y)				\
    do { x =((unsigned)((y)[3] & 255)<<24) |	\
	    ((unsigned)((y)[2] & 255)<<16) |	\
	    ((unsigned)((y)[1] & 255)<< 8) |	\
	    ((unsigned)((y)[0] & 255));		\
} while(0)

#define STORE32L(x, y)					\
    do {(y)[3] = (unsigned char)(((x)>>24)&255);	\
	(y)[2] = (unsigned char)(((x)>>16)&255);	\
	(y)[1] = (unsigned char)(((x)>> 8)&255);	\
	(y)[0] = (unsigned char)((x)&255);		\
} while(0)




#pragma mark - INLINE

static inline void _salsa_block(unsigned char *output, const unsigned *input, int rounds)
{
    unsigned x[16];
    int i;
    memcpy(x, input, sizeof(x));
    for (i = rounds; i > 0; i -= 2) {
	QUARTERROUND( 0, 4, 8,12)
	QUARTERROUND( 5, 9,13, 1)
	QUARTERROUND(10,14, 2, 6)
	QUARTERROUND(15, 3, 7,11)
	QUARTERROUND( 0, 1, 2, 3)
	QUARTERROUND( 5, 6, 7, 4)
	QUARTERROUND(10,11, 8, 9)
	QUARTERROUND(15,12,13,14)
    }
    for (i = 0; i < 16; ++i) {
	x[i] += input[i];
	STORE32L(x[i], output + 4 * i);
    }
}

static inline void _xsalsa_block(unsigned *x, int rounds)
{
    int i;

    for (i = rounds; i > 0; i -= 2) {
	QUARTERROUND( 0, 4, 8,12)
	QUARTERROUND( 5, 9,13, 1)
	QUARTERROUND(10,14, 2, 6)
	QUARTERROUND(15, 3, 7,11)
	QUARTERROUND( 0, 1, 2, 3)
	QUARTERROUND( 5, 6, 7, 4)
	QUARTERROUND(10,11, 8, 9)
	QUARTERROUND(15,12,13,14)
    }
}

static inline int _salsa_crypt(const unsigned char *in, unsigned char *out, unsigned long inlen, cipher_state *cs)
{
    unsigned char buf[64];
    unsigned long i, j;

    if (inlen == 0) return NBSCrypto_OK;

    if (cs->salsa.ksleft > 0) {
	j = MIN(cs->salsa.ksleft, inlen);
	for (i = 0; i < j; ++i, cs->salsa.ksleft--) out[i] = in[i] ^ cs->salsa.kstream[64 - cs->salsa.ksleft];
	inlen -= j;
	if (inlen == 0) return NBSCrypto_OK;
	out += j;
	in  += j;
    }
    for (;;) {
	_salsa_block(buf, cs->salsa.input, cs->salsa.rounds);
	if (0 == ++cs->salsa.input[8] && 0 == ++cs->salsa.input[9]) return NBSCrypto_ERROR;

	if (inlen <= 64) {
	    for (i = 0; i < inlen; ++i) out[i] = in[i] ^ buf[i];
	    cs->salsa.ksleft = 64 - inlen;
	    for (i = inlen; i < 64; ++i) cs->salsa.kstream[i] = buf[i];
	    return NBSCrypto_OK;
	}

	for (i = 0; i < 64; ++i) out[i] = in[i] ^ buf[i];
	inlen -= 64;
	out += 64;
	in  += 64;
    }
}




#pragma mark - FUNCTIONS
int salsa_setiv(const unsigned char *iv, unsigned long ivlen, unsigned long long counter, cipher_state *cs)
{

    LOAD32L(cs->salsa.input[6], iv + 0);
    LOAD32L(cs->salsa.input[7], iv + 4);
    cs->salsa.input[8] = (unsigned)(counter & 0xFFFFFFFF);
    cs->salsa.input[9] = (unsigned)(counter >> 32);
    cs->salsa.ksleft = 0;
    cs->salsa.ivlen = ivlen;

    return NBSCrypto_OK;
}

int salsa_setup(const unsigned char *key, int keylen, int rounds, cipher_state *cs)
{
    const char * const sigma = "expand 32-byte k";
    const char * const tau   = "expand 16-byte k";
    const char *constants;

    if (rounds == 0) rounds = 20;

    LOAD32L(cs->salsa.input[1],  key +  0);
    LOAD32L(cs->salsa.input[2],  key +  4);
    LOAD32L(cs->salsa.input[3],  key +  8);
    LOAD32L(cs->salsa.input[4],  key + 12);

    if (keylen == 32) {
	key += 16;
	constants = sigma;
    }else{
	constants = tau;
    }

    LOAD32L(cs->salsa.input[11], key +  0);
    LOAD32L(cs->salsa.input[12], key +  4);
    LOAD32L(cs->salsa.input[13], key +  8);
    LOAD32L(cs->salsa.input[14], key + 12);
    LOAD32L(cs->salsa.input[ 0], constants +  0);
    LOAD32L(cs->salsa.input[ 5], constants +  4);
    LOAD32L(cs->salsa.input[10], constants +  8);
    LOAD32L(cs->salsa.input[15], constants + 12);
    cs->salsa.rounds = rounds;
    cs->salsa.ivlen = 0;

    return NBSCrypto_OK;
}

int xsalsa_setup(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, int rounds, cipher_state *cs)
{
    int i;
    const char * const constants = "expand 32-byte k";
    const int sti[] = {0, 5, 10, 15, 6, 7, 8, 9};
    unsigned x[64];
    unsigned char subkey[32];

    if (rounds == 0) rounds = 20;

    LOAD32L(x[ 0], constants +  0);
    LOAD32L(x[ 5], constants +  4);
    LOAD32L(x[10], constants +  8);
    LOAD32L(x[15], constants + 12);
    LOAD32L(x[ 1], key +  0);
    LOAD32L(x[ 2], key +  4);
    LOAD32L(x[ 3], key +  8);
    LOAD32L(x[ 4], key + 12);
    LOAD32L(x[11], key + 16);
    LOAD32L(x[12], key + 20);
    LOAD32L(x[13], key + 24);
    LOAD32L(x[14], key + 28);
    LOAD32L(x[ 6], nonce +  0);
    LOAD32L(x[ 7], nonce +  4);
    LOAD32L(x[ 8], nonce +  8);
    LOAD32L(x[ 9], nonce + 12);

    _xsalsa_block(x, rounds);

    for (i = 0; i < 8; ++i) {
	STORE32L(x[sti[i]], subkey + 4 * i);
    }

    LOAD32L(cs->salsa.input[ 0], constants +  0);
    LOAD32L(cs->salsa.input[ 5], constants +  4);
    LOAD32L(cs->salsa.input[10], constants +  8);
    LOAD32L(cs->salsa.input[15], constants + 12);
    LOAD32L(cs->salsa.input[ 1], subkey +  0);
    LOAD32L(cs->salsa.input[ 2], subkey +  4);
    LOAD32L(cs->salsa.input[ 3], subkey +  8);
    LOAD32L(cs->salsa.input[ 4], subkey + 12);
    LOAD32L(cs->salsa.input[11], subkey + 16);
    LOAD32L(cs->salsa.input[12], subkey + 20);
    LOAD32L(cs->salsa.input[13], subkey + 24);
    LOAD32L(cs->salsa.input[14], subkey + 28);
    LOAD32L(cs->salsa.input[ 6], &(nonce[16]) + 0);
    LOAD32L(cs->salsa.input[ 7], &(nonce[16]) + 4);
    cs->salsa.input[ 8] = 0;
    cs->salsa.input[ 9] = 0;
    cs->salsa.rounds = rounds;
    cs->salsa.ksleft = 0;
    cs->salsa.ivlen  = 24;

    return NBSCrypto_OK;
}

int salsa_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cipher_state *cs)
{
    return _salsa_crypt(pt, ct, len, cs);
}

int salsa_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cipher_state *cs)
{
    return _salsa_crypt(ct, pt, len, cs);
}

void salsa_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->salsa));
}

