//
//	noekeon.c
//	Authors / Developers		: Joan Daemen, Michaël Peeters, Gilles van Assche, Vincent Rijmen
//	Last Modified (Original)	: November 2000
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor noekeon_desc =
{
    "noekeon",
    20,
    16, 16, 16, 16,
    &noekeon_setup,
    &noekeon_encrypt,
    &noekeon_decrypt,
    &noekeon_done
};




#pragma mark - DEFINES

#define PI1(a, b, c, d) b = ROLc(b, 1); c = ROLc(c, 5); d = ROLc(d, 2);
#define PI2(a, b, c, d) b = RORc(b, 1); c = RORc(c, 5); d = RORc(d, 2);

#define kTHETA(a, b, c, d)			\
    temp = a^c;					\
    temp = temp ^ ROLc(temp, 8) ^ RORc(temp, 8);\
    b ^= temp;					\
    d ^= temp;					\
    temp = b^d;					\
    temp = temp ^ ROLc(temp, 8) ^ RORc(temp, 8);\
    a ^= temp;					\
    c ^= temp;

#define THETA(k, a, b, c, d)			\
    temp = a^c;					\
    temp = temp ^ ROLc(temp, 8) ^ RORc(temp, 8);\
    b ^= temp ^ k[1];				\
    d ^= temp ^ k[3];				\
    temp = b^d;					\
    temp = temp ^ ROLc(temp, 8) ^ RORc(temp, 8);\
    a ^= temp ^ k[0];				\
    c ^= temp ^ k[2];

#define GAMMA(a, b, c, d)			\
    b ^= ~(d|c);				\
    a ^= c&b;					\
    temp = d;					\
    d = a;					\
    a = temp;					\
    c ^= a ^ b ^ d;				\
    b ^= ~(d|c);				\
    a ^= c&b;

#define eKROUND(i)				\
    a ^= RC[i];					\
    THETA(cs->noekeon.eK, a,b,c,d);		\
    PI1(a,b,c,d);				\
    GAMMA(a,b,c,d);				\
    PI2(a,b,c,d);

#define dKROUND(i)				\
    THETA(cs->noekeon.dK, a,b,c,d);		\
    a ^= RC[i];					\
    PI1(a,b,c,d);				\
    GAMMA(a,b,c,d);				\
    PI2(a,b,c,d);

#define STORE32(x, y)										\
    do {(y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);	\
	(y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD32(x, y)										\
    do {x = ((unsigned)((y)[0] & 255)<<24) | ((unsigned)((y)[1] & 255)<<16) |			\
	    ((unsigned)((y)[2] & 255)<<8)  | ((unsigned)((y)[3] & 255));			\
} while(0)

#define ROLc(x, y) ((((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)
#define RORc(x, y) (((((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((y)&31)) | ((unsigned)(x)<<(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)


static const unsigned RC[] = {
    0x00000080UL, 0x0000001bUL, 0x00000036UL, 0x0000006cUL, 0x000000d8UL, 0x000000abUL, 0x0000004dUL, 0x0000009aUL,
    0x0000002fUL, 0x0000005eUL, 0x000000bcUL, 0x00000063UL, 0x000000c6UL, 0x00000097UL, 0x00000035UL, 0x0000006aUL,
    0x000000d4UL
};




#pragma mark - FUNCTIONS
int noekeon_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    unsigned temp;

    if(keylen!=16) {
	return NBSCrypto_ERROR;
    }

    if (num_rounds != 16 && num_rounds != 0) {
	return NBSCrypto_ERROR;
    }

    LOAD32(cs->noekeon.eK[0],&key[ 0]);
    LOAD32(cs->noekeon.eK[1],&key[ 4]);
    LOAD32(cs->noekeon.eK[2],&key[ 8]);
    LOAD32(cs->noekeon.eK[3],&key[12]);

    LOAD32(cs->noekeon.dK[0],&key[ 0]);
    LOAD32(cs->noekeon.dK[1],&key[ 4]);
    LOAD32(cs->noekeon.dK[2],&key[ 8]);
    LOAD32(cs->noekeon.dK[3],&key[12]);

    kTHETA(cs->noekeon.dK[0], cs->noekeon.dK[1], cs->noekeon.dK[2], cs->noekeon.dK[3]);

    return NBSCrypto_OK;
}

int noekeon_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    unsigned a,b,c,d,temp;
    int r;

    LOAD32(a,&pt[ 0]);
    LOAD32(b,&pt[ 4]);
    LOAD32(c,&pt[ 8]);
    LOAD32(d,&pt[12]);

    for (r = 0; r < 16; ++r) {
	eKROUND(r);
    }

    a ^= RC[16];
    THETA(cs->noekeon.eK, a, b, c, d);

    STORE32(a,&ct[ 0]);
    STORE32(b,&ct[ 4]);
    STORE32(c,&ct[ 8]);
    STORE32(d,&ct[12]);

    return NBSCrypto_OK;
}

int noekeon_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    unsigned a,b,c,d,temp;
    int r;

    LOAD32(a,&ct[ 0]);
    LOAD32(b,&ct[ 4]);
    LOAD32(c,&ct[ 8]);
    LOAD32(d,&ct[12]);

    for (r = 16; r > 0; --r) {
	dKROUND(r);
    }

    THETA(cs->noekeon.dK, a,b,c,d);
    a ^= RC[0];
    STORE32(a,&pt[ 0]);
    STORE32(b,&pt[ 4]);
    STORE32(c,&pt[ 8]);
    STORE32(d,&pt[12]);
    return NBSCrypto_OK;
}

void noekeon_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->noekeon));
}
