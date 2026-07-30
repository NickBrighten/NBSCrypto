//
//	tea.c
//	Authors / Developers		: David Wheeler, Roger Needham
//	Last Modified (Original)	: 1994
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor tea_desc =
{
    "tea",
    39,
    16, 16, 8, 32,
    &tea_setup,
    &tea_encrypt,
    &tea_decrypt,
    &tea_done
};




#pragma mark - DEFINES

#define DELTA 0x9E3779B9
#define SUM 0xC6EF3720

#define STORE32(x, y)					\
    do {(y)[0] = (unsigned char)(((x)>>24)&255);	\
	(y)[1] = (unsigned char)(((x)>>16)&255);	\
	(y)[2] = (unsigned char)(((x)>> 8)&255);	\
	(y)[3] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD32(x, y)				\
    do {x = ((unsigned)((y)[0] & 255)<<24) |	\
	    ((unsigned)((y)[1] & 255)<<16) |	\
	    ((unsigned)((y)[2] & 255)<< 8) |	\
	    ((unsigned)((y)[3] & 255));		\
} while(0)




#pragma mark - FUNCTIONS

int tea_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    if (keylen != 16) {
	return NBSCrypto_ERROR;
    }

    if (num_rounds != 0 && num_rounds != 32) {
	return NBSCrypto_ERROR;
    }

    LOAD32(cs->tea.k[0], key+ 0);
    LOAD32(cs->tea.k[1], key+ 4);
    LOAD32(cs->tea.k[2], key+ 8);
    LOAD32(cs->tea.k[3], key+12);

    return NBSCrypto_OK;
}

int tea_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    unsigned y, z, sum = 0;
    const unsigned delta = DELTA;
    int r;

    LOAD32(y, &pt[0]);
    LOAD32(z, &pt[4]);
    for (r = 0; r < 32; r++) {
	sum += delta;
	y += ((z<<4) + cs->tea.k[0]) ^ (z + sum) ^ ((z>>5) + cs->tea.k[1]);
	z += ((y<<4) + cs->tea.k[2]) ^ (y + sum) ^ ((y>>5) + cs->tea.k[3]);
    }
    STORE32(y, &ct[0]);
    STORE32(z, &ct[4]);
    return NBSCrypto_OK;
}

int tea_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    unsigned v0, v1, sum = SUM;
    const unsigned delta = DELTA;
    int r;

    LOAD32(v0, &ct[0]);
    LOAD32(v1, &ct[4]);

    for (r = 0; r < 32; r++) {
	v1 -= ((v0 << 4) + cs->tea.k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + cs->tea.k[3]);
	v0 -= ((v1 << 4) + cs->tea.k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + cs->tea.k[1]);
	sum -= delta;
    }

    STORE32(v0, &pt[0]);
    STORE32(v1, &pt[4]);
    return NBSCrypto_OK;
}

void tea_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->tea));
}
