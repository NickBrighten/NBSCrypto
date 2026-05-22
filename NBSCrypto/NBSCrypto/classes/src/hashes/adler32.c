//
//	adler32.c
//	Authors / Developers		: Mark Adler
//	Last Modified (Original)	: 1995
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor adler32_desc =
{
    "adler32",
    1,
    4,
    4,
    &adler32_init,
    &adler32_process,
    &adler32_done,
    NULL
};




#pragma mark - DEFINES
static const unsigned long ADLER32_BASE = 65521;




#pragma mark - FUNCTIONS
int adler32_init(hash_state *hs)
{
    hs->adler32.s[0] = 1;
    hs->adler32.s[1] = 0;

    return NBSCrypto_OK;
}

int adler32_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long s1, s2;

    s1 = hs->adler32.s[0];
    s2 = hs->adler32.s[1];

    if (inlen % 8 != 0) {
	do {
	    s1 += *in++;
	    s2 += s1;
	    inlen--;
	} while (inlen % 8 != 0);

	if (s1 >= ADLER32_BASE) {
	    s1 -= ADLER32_BASE;
	}
	s2 %= ADLER32_BASE;
    }

    while (inlen > 0) {
	s1 += in[0];
	s2 += s1;
	s1 += in[1];
	s2 += s1;
	s1 += in[2];
	s2 += s1;
	s1 += in[3];
	s2 += s1;
	s1 += in[4];
	s2 += s1;
	s1 += in[5];
	s2 += s1;
	s1 += in[6];
	s2 += s1;
	s1 += in[7];
	s2 += s1;

	inlen -= 8;
	in += 8;

	if (s1 >= ADLER32_BASE) {
	    s1 -= ADLER32_BASE;
	}
	s2 %= ADLER32_BASE;
    }

    hs->adler32.s[0] = (unsigned short)s1;
    hs->adler32.s[1] = (unsigned short)s2;

    return NBSCrypto_OK;
}

int adler32_done(hash_state *hs, unsigned char *out)
{
    switch(sizeof(out)){
	default:{out[3] =  hs->adler32.s[0] & 0x0ff;}
	case 3: {out[2] = (hs->adler32.s[0] >> 8) & 0x0ff;}
	case 2: {out[1] =  hs->adler32.s[1] & 0x0ff;}
	case 1: {out[0] = (hs->adler32.s[1] >> 8) & 0x0ff;}
	case 0: {}
    }

    return NBSCrypto_OK;
}
