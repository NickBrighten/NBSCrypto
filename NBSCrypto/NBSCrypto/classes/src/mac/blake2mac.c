//
//	blake2mac.c
//	Authors / Developers		: Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn,
//					  Christian Winnerlein
//	Last Modified (Original)	: 2012
//

#include "nbs_crypto.h"




#pragma mark FUNCTIONS
int blake2bmac_init(const unsigned char *key, unsigned long keylen, unsigned long outlen, blake2bmac_state *b2bmac)
{
    return blake2b_init(b2bmac, outlen, key, keylen);
}

int blake2bmac_process(const unsigned char *in, unsigned long inlen, blake2bmac_state *b2bmac)
{
    if (inlen == 0) return NBSCrypto_ERROR;
    return blake2b_process(b2bmac, in, inlen);
}

int blake2bmac_done(unsigned char *out, unsigned long *outlen, blake2bmac_state *b2bmac)
{
    if (*outlen > b2bmac->blake2b.outlen) {
	return NBSCrypto_ERROR;
    }

    *outlen = b2bmac->blake2b.outlen;
    return blake2b_done(b2bmac, out);
}

int blake2smac_init(const unsigned char *key, unsigned long keylen, unsigned long outlen, blake2smac_state *b2smac)
{
    return blake2s_init(b2smac, outlen, key, keylen);
}

int blake2smac_process(const unsigned char *in, unsigned long inlen, blake2smac_state *b2smac)
{
    if (inlen == 0) return NBSCrypto_ERROR;
    return blake2s_process(b2smac, in, inlen);
}

int blake2smac_done(unsigned char *out, unsigned long *outlen, blake2smac_state *b2smac)
{
    if (*outlen > b2smac->blake2s.outlen) {
	return NBSCrypto_ERROR;
    }

    *outlen = b2smac->blake2s.outlen;
    return blake2s_done(b2smac, out);
}
