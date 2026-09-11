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
    unsigned long k1;
    //cm_ECB *skey;
    cipher_state skey;

    xcbc->cipher = cipher;

    if ((err = is_cipher_valid(xcbc->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (keylen & XCBC_PURE) {
	keylen &= ~XCBC_PURE;

	if (keylen < 2UL * cipher_descriptor[xcbc->cipher].block_length) {
	    return NBSCrypto_ERROR;
	}

	k1 = keylen - 2*cipher_descriptor[xcbc->cipher].block_length;
	memcpy(xcbc->K[0], key, k1);
	memcpy(xcbc->K[1], key+k1, cipher_descriptor[xcbc->cipher].block_length);
	memcpy(xcbc->K[2], key+k1 + cipher_descriptor[xcbc->cipher].block_length, cipher_descriptor[xcbc->cipher].block_length);
    } else {
	k1 = cipher_descriptor[xcbc->cipher].block_length;

	if ((err = cipher_descriptor[xcbc->cipher].setup(key, (int)keylen, 0, &skey)) != NBSCrypto_OK) {
	    goto done;
	}

	for (y = 0; y < 3; y++) {
	    for (x = 0; x < cipher_descriptor[xcbc->cipher].block_length; x++) {
		xcbc->K[y][x] = y + 1;
	    }
	    cipher_descriptor[xcbc->cipher].encrypt(xcbc->K[y], xcbc->K[y], &skey);
	}
    }

    err = cipher_descriptor[xcbc->cipher].setup(xcbc->K[0], (int)k1, 0, &xcbc->cs);

    zeromem(xcbc->IV, cipher_descriptor[xcbc->cipher].block_length);
    xcbc->blocksize = cipher_descriptor[xcbc->cipher].block_length;
    xcbc->buflen    = 0;
done:
    cipher_descriptor[xcbc->cipher].done(&skey);
    return err;
}

int xcbc_process(const unsigned char *in, unsigned long inlen, xcbc_state *xcbc)
{

    if ((xcbc->blocksize < 0) || (xcbc->buflen > xcbc->blocksize) || (xcbc->buflen < 0)) {
	return NBSCrypto_ERROR;
    }

    while (inlen) {
	if (xcbc->buflen == xcbc->blocksize) {
	    cipher_descriptor[xcbc->cipher].encrypt(xcbc->IV, xcbc->IV, &xcbc->cs);
	    //ecb_encrypt_block(xcbc->IV, xcbc->IV, &xcbc->key);
	    xcbc->buflen = 0;
	}
	xcbc->IV[xcbc->buflen++] ^= *in++;
	--inlen;
    }
    return NBSCrypto_OK;
}

int xcbc_done(unsigned char *out, unsigned long *outlen, xcbc_state *xcbc)
{
    int x;

    if ((xcbc->blocksize < 0) || (xcbc->buflen > xcbc->blocksize) || (xcbc->buflen < 0)) {
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
