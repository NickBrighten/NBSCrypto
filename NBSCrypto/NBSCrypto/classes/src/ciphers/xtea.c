//
//	xtea.c
//	Authors / Developers		: Roger Needham, David Wheeler
//	Last Modified (Original)	: 1997
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor xtea_desc =
{
    "xtea",
    40,
    16, 16, 8, 32,
    &xtea_setup,
    &xtea_encrypt,
    &xtea_decrypt,
    &xtea_done
};




#pragma mark - DEFINES

#define STORE32(x, y)					\
    do {(y)[0] = (unsigned char)(((x)>>24)&255);	\
	(y)[1] = (unsigned char)(((x)>>16)&255);	\
	(y)[2] = (unsigned char)(((x)>> 8)&255);	\
	(y)[3] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD32(x, y)				\
    do {x = ((unsigned)((y)[0] & 255)<<24) |	\
	    ((unsigned)((y)[1] & 255)<<16) |	\
	    ((unsigned)((y)[2] & 255)<< 8) | 	\
	    ((unsigned)((y)[3] & 255));		\
} while(0)




#pragma mark - FUNCTIONS

int xtea_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    unsigned long x, sum, K[4];

    if (keylen != 16) {
	return NBSCrypto_ERROR;
    }

    if (num_rounds != 0 && num_rounds != 32) {
	return NBSCrypto_ERROR;
    }

    LOAD32(K[0], key+ 0);
    LOAD32(K[1], key+ 4);
    LOAD32(K[2], key+ 8);
    LOAD32(K[3], key+12);

    for (x = sum = 0; x < 32; x++) {
	cs->xtea.A[x] = (sum + K[sum&3]) & 0xFFFFFFFF;
	sum = (sum + 0x9E3779B9) & 0xFFFFFFFF;
	cs->xtea.B[x] = (sum + K[(sum>>11)&3]) & 0xFFFFFFFF;
    }

    return NBSCrypto_OK;
}

int xtea_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    unsigned long y, z;
    int r;

    LOAD32(y, &pt[0]);
    LOAD32(z, &pt[4]);
    for (r = 0; r < 32; r += 4) {
	y = (y + ((((z<<4)^(z>>5)) + z) ^ cs->xtea.A[r])) & 0xFFFFFFFF;
	z = (z + ((((y<<4)^(y>>5)) + y) ^ cs->xtea.B[r])) & 0xFFFFFFFF;

	y = (y + ((((z<<4)^(z>>5)) + z) ^ cs->xtea.A[r+1])) & 0xFFFFFFFF;
	z = (z + ((((y<<4)^(y>>5)) + y) ^ cs->xtea.B[r+1])) & 0xFFFFFFFF;

	y = (y + ((((z<<4)^(z>>5)) + z) ^ cs->xtea.A[r+2])) & 0xFFFFFFFF;
	z = (z + ((((y<<4)^(y>>5)) + y) ^ cs->xtea.B[r+2])) & 0xFFFFFFFF;

	y = (y + ((((z<<4)^(z>>5)) + z) ^ cs->xtea.A[r+3])) & 0xFFFFFFFF;
	z = (z + ((((y<<4)^(y>>5)) + y) ^ cs->xtea.B[r+3])) & 0xFFFFFFFF;
    }
    STORE32(y, &ct[0]);
    STORE32(z, &ct[4]);

    return NBSCrypto_OK;
}

int xtea_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    unsigned long y, z;
    int r;

    LOAD32(y, &ct[0]);
    LOAD32(z, &ct[4]);

    for (r = 31; r >= 0; r -= 4) {
	z = (z - ((((y<<4)^(y>>5)) + y) ^ cs->xtea.B[r])) & 0xFFFFFFFF;
	y = (y - ((((z<<4)^(z>>5)) + z) ^ cs->xtea.A[r])) & 0xFFFFFFFF;

	z = (z - ((((y<<4)^(y>>5)) + y) ^ cs->xtea.B[r-1])) & 0xFFFFFFFF;
	y = (y - ((((z<<4)^(z>>5)) + z) ^ cs->xtea.A[r-1])) & 0xFFFFFFFF;

	z = (z - ((((y<<4)^(y>>5)) + y) ^ cs->xtea.B[r-2])) & 0xFFFFFFFF;
	y = (y - ((((z<<4)^(z>>5)) + z) ^ cs->xtea.A[r-2])) & 0xFFFFFFFF;

	z = (z - ((((y<<4)^(y>>5)) + y) ^ cs->xtea.B[r-3])) & 0xFFFFFFFF;
	y = (y - ((((z<<4)^(z>>5)) + z) ^ cs->xtea.A[r-3])) & 0xFFFFFFFF;
    }

    STORE32(y, &pt[0]);
    STORE32(z, &pt[4]);

    return NBSCrypto_OK;
}

void xtea_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->xtea));
}
