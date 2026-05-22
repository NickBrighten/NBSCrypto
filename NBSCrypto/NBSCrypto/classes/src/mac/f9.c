//
//	f9.c
//

#include "nbs_crypto.h"


int f9_init(int cipher, const unsigned char *key, unsigned long keylen, f9_state *f9)
{
    int x, err;

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((err = cipher_descriptor[cipher].setup(key, (int)keylen, 0, &f9->cs)) != NBSCrypto_OK) {
	goto done;
    }

    for (x = 0; (unsigned)x < keylen; x++) {
	f9->akey[x] = key[x] ^ 0xAA;
    }

    zeromem(f9->IV,  cipher_descriptor[cipher].block_length);
    zeromem(f9->ACC, cipher_descriptor[cipher].block_length);
    f9->block_len = cipher_descriptor[cipher].block_length;
    f9->cipher    = cipher;
    f9->buflen    = 0;
    f9->keylen    = (int)keylen;

done:
    return err;
}

int f9_process(const unsigned char *in, unsigned long inlen, f9_state *f9)
{
    int err, x;

    if ((err = is_cipher_valid(f9->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((f9->block_len > cipher_descriptor[f9->cipher].block_length) || (f9->block_len < 0) ||
	(f9->buflen > f9->block_len) || (f9->buflen < 0)) {
	return NBSCrypto_ERROR;
    }

    while (inlen) {
	if (f9->buflen == f9->block_len) {
	    cipher_descriptor[f9->cipher].encrypt(f9->IV, f9->IV, &f9->cs);
	    for (x = 0; x < f9->block_len; x++) {
		f9->ACC[x] ^= f9->IV[x];
	    }
	    f9->buflen = 0;
	}
	f9->IV[f9->buflen++] ^= *in++;
	--inlen;
    }

    return NBSCrypto_OK;
}

int f9_done(unsigned char *out, unsigned long *outlen, f9_state *f9)
{
    int err, x;

    if ((err = is_cipher_valid(f9->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((f9->block_len > cipher_descriptor[f9->cipher].block_length) || (f9->block_len < 0) ||
	(f9->buflen > f9->block_len) || (f9->buflen < 0)) {
	return NBSCrypto_ERROR;
    }

    if (f9->buflen != 0) {
	cipher_descriptor[f9->cipher].encrypt(f9->IV, f9->IV, &f9->cs);
	f9->buflen = 0;
	for (x = 0; x < f9->block_len; x++) {
	    f9->ACC[x] ^= f9->IV[x];
	}
    }

    if ((err = cipher_descriptor[f9->cipher].setup(f9->akey, f9->keylen, 0, &f9->cs)) != NBSCrypto_OK) {
	return err;
    }

    cipher_descriptor[f9->cipher].encrypt(f9->ACC, f9->ACC, &f9->cs);
    cipher_descriptor[f9->cipher].done(&f9->cs);

    for (x = 0; x < f9->block_len && (unsigned long)x < *outlen; x++) {
	out[x] = f9->ACC[x];
    }

    *outlen = x;

    return NBSCrypto_OK;
}

