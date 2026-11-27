//
//	xcbc.c
//	Authors / Developers		: John Black, Phillip Rogaway
//	Last Modified (Original)	: 2000
//

#include "nbs_crypto.h"




#pragma mark DEFINES
#define XCBC_PURE	0x8000UL




#pragma mark - FUNCTIONS
int xcbc_init(unsigned long cipher, const unsigned char *key, unsigned long keylen, xcbc_state *xcbc)
{
    int x, y, err;
    int skey_init = 0;
    unsigned long k1;
    cipher_state cs;


    if (key == NULL || xcbc == NULL) {
	return NBSCrypto_ERROR;
    }

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }
    xcbc->cipher = cipher;

    if (keylen & XCBC_PURE) {
	keylen &= ~XCBC_PURE;

	if (keylen < 2UL * cipher_descriptor[xcbc->cipher].block_length) {
	    return NBSCrypto_ERROR;
	}

	k1 = keylen - 2 * cipher_descriptor[xcbc->cipher].block_length;
	if (k1 > sizeof(xcbc->K[0]) || k1 > (unsigned long)INT_MAX) {
	    return NBSCrypto_ERROR;
	}
	memcpy(xcbc->K[0], key, k1);
	memcpy(xcbc->K[1], key+k1, cipher_descriptor[xcbc->cipher].block_length);
	memcpy(xcbc->K[2], key+k1 + cipher_descriptor[xcbc->cipher].block_length, cipher_descriptor[xcbc->cipher].block_length);
    } else {
	k1 = cipher_descriptor[xcbc->cipher].block_length;

	if (keylen > (unsigned long)INT_MAX) {
	    return NBSCrypto_ERROR;
	}

	if ((err = cipher_descriptor[xcbc->cipher].setup(key, (int)keylen, 0, &cs)) != NBSCrypto_OK) {
	    goto done;
	}

	skey_init = 1;

	for (y = 0; y < 3; y++) {
	    for (x = 0; x < cipher_descriptor[xcbc->cipher].block_length; x++) {
		xcbc->K[y][x] = y + 1;
	    }
	    cipher_descriptor[xcbc->cipher].encrypt(xcbc->K[y], xcbc->K[y], &cs);
	}
    }

    if ((err = cipher_descriptor[xcbc->cipher].setup(xcbc->K[0], (int)k1, 0, &xcbc->cs)) != NBSCrypto_OK) {
	zeromem(xcbc, sizeof(*xcbc));
	goto done;
    }

    zeromem(xcbc->IV, cipher_descriptor[xcbc->cipher].block_length);
    xcbc->blocksize = cipher_descriptor[xcbc->cipher].block_length;
    xcbc->buflen    = 0;

done:
    if(skey_init){
	cipher_descriptor[xcbc->cipher].done(&cs);
    }
    return err;
}

int xcbc_process(const unsigned char *in, unsigned long inlen, xcbc_state *xcbc)
{
    int err;

    if (xcbc == NULL || (in == NULL && inlen > 0)) {
	return NBSCrypto_ERROR;
    }

    if ((err = is_cipher_valid(xcbc->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((xcbc->blocksize <= 0) || (xcbc->blocksize > (int)sizeof(xcbc->IV)) ||
	(xcbc->buflen > xcbc->blocksize) || (xcbc->buflen < 0)) {
	return NBSCrypto_ERROR;
    }

    while (inlen) {
	if (xcbc->buflen == xcbc->blocksize) {
	    cipher_descriptor[xcbc->cipher].encrypt(xcbc->IV, xcbc->IV, &xcbc->cs);
	    xcbc->buflen = 0;
	}
	xcbc->IV[xcbc->buflen++] ^= *in++;
	--inlen;
    }
    return NBSCrypto_OK;
}

int xcbc_done(unsigned char *out, unsigned long *outlen, xcbc_state *xcbc)
{
    int x, err;

    if (out == NULL || outlen == NULL || xcbc == NULL) {
	return NBSCrypto_ERROR;
    }

    if ((err = is_cipher_valid(xcbc->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((xcbc->blocksize <= 0) || (xcbc->blocksize > (int)sizeof(xcbc->IV)) ||
	(xcbc->buflen > xcbc->blocksize) || (xcbc->buflen < 0)) {
	return NBSCrypto_ERROR;
    }

    if (*outlen == 0) {
	return NBSCrypto_ERROR;
    }

    if (xcbc->buflen == xcbc->blocksize) {
	for (x = 0; x < xcbc->blocksize; x++) {
	    xcbc->IV[x] ^= xcbc->K[1][x];
	}
    } else {
	xcbc->IV[xcbc->buflen] ^= 0x80;
	for (x = 0; x < xcbc->blocksize; x++) {
	    xcbc->IV[x] ^= xcbc->K[2][x];
	}
    }

    cipher_descriptor[xcbc->cipher].encrypt(xcbc->IV, xcbc->IV, &xcbc->cs);
    cipher_descriptor[xcbc->cipher].done(&xcbc->cs);

    for (x = 0; x < xcbc->blocksize && (unsigned long)x < *outlen; x++) {
	out[x] = xcbc->IV[x];
    }
    *outlen = x;

    zeromem(xcbc, sizeof(*xcbc));

    return NBSCrypto_OK;
}
