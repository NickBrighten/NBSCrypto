//
//	rc2.c
//	Authors / Developers		: Ronald L. Rivest
//	Last Modified (Original)	: 1987
//


#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor rc2_desc =
{
    "rc2",
    23,
    1, 128, 8, 16,
    &rc2_setup,
    &rc2_encrypt,
    &rc2_decrypt,
    &rc2_done,
};




#pragma mark - DEFINES

static const unsigned char permute[256] = {
    217,120,249,196, 25,221,181,237, 40,233,253,121, 74,160,216,157,
    198,126, 55,131, 43,118, 83,142, 98, 76,100,136, 68,139,251,162,
     23,154, 89,245,135,179, 79, 19, 97, 69,109,141,  9,129,125, 50,
    189,143, 64,235,134,183,123, 11,240,149, 33, 34, 92,107, 78,130,
     84,214,101,147,206, 96,178, 28,115, 86,192, 20,167,140,241,220,
     18,117,202, 31, 59,190,228,209, 66, 61,212, 48,163, 60,182, 38,
    111,191, 14,218, 70,105,  7, 87, 39,242, 29,155,188,148, 67,  3,
    248, 17,199,246,144,239, 62,231,  6,195,213, 47,200,102, 30,215,
      8,232,234,222,128, 82,238,247,132,170,114,172, 53, 77,106, 42,
    150, 26,210,113, 90, 21, 73,116, 75,159,208, 94,  4, 24,164,236,
    194,224, 65,110, 15, 81,203,204, 36,145,175, 80,161,244,112, 57,
    153,124, 58,133, 35,184,180,122,252,  2, 54, 91, 37, 85,151, 49,
     45, 93,250,152,227,138,146,174,  5,223, 41, 16,103,108,186,201,
    211,  0,230,207,225,158,168, 44, 99, 22,  1, 63, 88,226,137,169,
     13, 56, 52, 27,171, 51,255,176,187, 72, 12, 95,185,177,205, 46,
    197,243,219, 71,229,165,156,119, 10,166, 32,104,254,127,193,173
};




#pragma mark - INLINE
static inline int _rc2_setup_ex(const unsigned char *key, int keylen, int bits, int num_rounds, cipher_state *cs)
{
    int i;
    unsigned *xkey = cs->rc2.xkey, T8, TM;
    unsigned char tmp[128];

    if (keylen == 0 || keylen > 128 || bits > 1024) {
	return NBSCrypto_ERROR;
    }

    if (bits == 0) {
	bits = 1024;
    }

    if (num_rounds != 0 && num_rounds != 16) {
	return NBSCrypto_ERROR;
    }

    for (i = 0; i < keylen; i++) {
	tmp[i] = key[i] & 255;
    }

    if (keylen < 128) {
	for (i = keylen; i < 128; i++) {
	    tmp[i] = permute[(tmp[i - 1] + tmp[i - keylen]) & 255];
	}
    }

    T8   = (unsigned)(bits+7)>>3;
    TM   = (255 >> (unsigned)(7 & -bits));
    tmp[128 - T8] = permute[tmp[128 - T8] & TM];
    for (i = 127 - T8; i >= 0; i--) {
	tmp[i] = permute[tmp[i + 1] ^ tmp[i + T8]];
    }

    for (i = 0; i < 64; i++) {
	xkey[i] =  (unsigned)tmp[2*i] + ((unsigned)tmp[2*i+1] << 8);
    }

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int rc2_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    return _rc2_setup_ex(key, keylen, keylen * 8, num_rounds, cs);
}

int rc2_encrypt( const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    const unsigned *xkey;
    unsigned x76, x54, x32, x10, i;

    xkey = cs->rc2.xkey;

    x76 = ((unsigned)pt[7] << 8) + (unsigned)pt[6];
    x54 = ((unsigned)pt[5] << 8) + (unsigned)pt[4];
    x32 = ((unsigned)pt[3] << 8) + (unsigned)pt[2];
    x10 = ((unsigned)pt[1] << 8) + (unsigned)pt[0];

    for (i = 0; i < 16; i++) {
	x10 = (x10 + (x32 & ~x76) + (x54 & x76) + xkey[4*i+0]) & 0xFFFF;
	x10 = ((x10 << 1) | (x10 >> 15));

	x32 = (x32 + (x54 & ~x10) + (x76 & x10) + xkey[4*i+1]) & 0xFFFF;
	x32 = ((x32 << 2) | (x32 >> 14));

	x54 = (x54 + (x76 & ~x32) + (x10 & x32) + xkey[4*i+2]) & 0xFFFF;
	x54 = ((x54 << 3) | (x54 >> 13));

	x76 = (x76 + (x10 & ~x54) + (x32 & x54) + xkey[4*i+3]) & 0xFFFF;
	x76 = ((x76 << 5) | (x76 >> 11));

	if (i == 4 || i == 10) {
	    x10 = (x10 + xkey[x76 & 63]) & 0xFFFF;
	    x32 = (x32 + xkey[x10 & 63]) & 0xFFFF;
	    x54 = (x54 + xkey[x32 & 63]) & 0xFFFF;
	    x76 = (x76 + xkey[x54 & 63]) & 0xFFFF;
	}
    }

    ct[0] = (unsigned char)x10;
    ct[1] = (unsigned char)(x10 >> 8);
    ct[2] = (unsigned char)x32;
    ct[3] = (unsigned char)(x32 >> 8);
    ct[4] = (unsigned char)x54;
    ct[5] = (unsigned char)(x54 >> 8);
    ct[6] = (unsigned char)x76;
    ct[7] = (unsigned char)(x76 >> 8);

    return NBSCrypto_OK;
}

int rc2_decrypt( const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    int i;
    const unsigned *xkey;
    unsigned x76, x54, x32, x10;

    xkey = cs->rc2.xkey;

    x76 = ((unsigned)ct[7] << 8) + (unsigned)ct[6];
    x54 = ((unsigned)ct[5] << 8) + (unsigned)ct[4];
    x32 = ((unsigned)ct[3] << 8) + (unsigned)ct[2];
    x10 = ((unsigned)ct[1] << 8) + (unsigned)ct[0];

    for (i = 15; i >= 0; i--) {
	if (i == 4 || i == 10) {
	    x76 = (x76 - xkey[x54 & 63]) & 0xFFFF;
	    x54 = (x54 - xkey[x32 & 63]) & 0xFFFF;
	    x32 = (x32 - xkey[x10 & 63]) & 0xFFFF;
	    x10 = (x10 - xkey[x76 & 63]) & 0xFFFF;
	}

	x76 = ((x76 << 11) | (x76 >> 5));
	x76 = (x76 - ((x10 & ~x54) + (x32 & x54) + xkey[4*i+3])) & 0xFFFF;

	x54 = ((x54 << 13) | (x54 >> 3));
	x54 = (x54 - ((x76 & ~x32) + (x10 & x32) + xkey[4*i+2])) & 0xFFFF;

	x32 = ((x32 << 14) | (x32 >> 2));
	x32 = (x32 - ((x54 & ~x10) + (x76 & x10) + xkey[4*i+1])) & 0xFFFF;

	x10 = ((x10 << 15) | (x10 >> 1));
	x10 = (x10 - ((x32 & ~x76) + (x54 & x76) + xkey[4*i+0])) & 0xFFFF;
    }

    pt[0] = (unsigned char)x10;
    pt[1] = (unsigned char)(x10 >> 8);
    pt[2] = (unsigned char)x32;
    pt[3] = (unsigned char)(x32 >> 8);
    pt[4] = (unsigned char)x54;
    pt[5] = (unsigned char)(x54 >> 8);
    pt[6] = (unsigned char)x76;
    pt[7] = (unsigned char)(x76 >> 8);

    return NBSCrypto_OK;
}

void rc2_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->rc2));
}
