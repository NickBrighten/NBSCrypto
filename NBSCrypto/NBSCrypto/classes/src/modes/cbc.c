//
//	cbc.c
//	Authors / Developers		: William F. Ehrsam, Carl H. W. Meyer, John L. Smith, Walter L. Tuchman
//	Last Modified (Original)	: 1976
//

#include "nbs_crypto.h"




#pragma mark - FUNCTIONS
int cbc_start(unsigned long cipher, const unsigned char *iv, const unsigned char *key, int keylen, int num_rounds, cm_CBC *cbc)
{
    int x, err;

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((err = cipher_descriptor[cipher].setup(key, keylen, num_rounds, &cbc->cs)) != NBSCrypto_OK) {
	return err;
    }

    cbc->blocklen = cipher_descriptor[cipher].block_length;
    cbc->cipher   = cipher;

    for (x = 0; x < cbc->blocklen; x++) {
	cbc->IV[x] = iv[x];
    }

    return NBSCrypto_OK;
}

int cbc_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_CBC *cbc)
{
    int x, err;

    if ((err = is_cipher_valid(cbc->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (cbc->blocklen < 1 || cbc->blocklen > (int)sizeof(cbc->IV)) {
	return NBSCrypto_ERROR;
    }

    if (len % cbc->blocklen) {
	return NBSCrypto_ERROR;
    }

    if (cipher_descriptor[cbc->cipher].accel_cbc_encrypt != NULL) {
	return cipher_descriptor[cbc->cipher].accel_cbc_encrypt(pt, ct, len / cbc->blocklen, cbc->IV, &cbc->cs);
    }

    while (len) {
	for (x = 0; x < cbc->blocklen; x++) {
	    cbc->IV[x] ^= pt[x];
	}

	if ((err = cipher_descriptor[cbc->cipher].encrypt(cbc->IV, ct, &cbc->cs)) != NBSCrypto_OK) {
	    return err;
	}

	for (x = 0; x < cbc->blocklen; x++) {
	    cbc->IV[x] = ct[x];
	}

	ct  += cbc->blocklen;
	pt  += cbc->blocklen;
	len -= cbc->blocklen;
    }

    return NBSCrypto_OK;
}

int cbc_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_CBC *cbc)
{
    int x, err;
    unsigned char tmp[16];
    unsigned char tmpy;

    if ((err = is_cipher_valid(cbc->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (cbc->blocklen < 1 || cbc->blocklen > (int)sizeof(cbc->IV) || cbc->blocklen > (int)sizeof(tmp)) {
	return NBSCrypto_ERROR;
    }

    if (len % cbc->blocklen) {
	return NBSCrypto_ERROR;
    }

    if (cipher_descriptor[cbc->cipher].accel_cbc_decrypt != NULL) {
	return cipher_descriptor[cbc->cipher].accel_cbc_decrypt(ct, pt, len / cbc->blocklen, cbc->IV, &cbc->cs);
    }

    while (len) {
	if ((err = cipher_descriptor[cbc->cipher].decrypt(ct, tmp, &cbc->cs)) != NBSCrypto_OK) {
	    return err;
	}

	for (x = 0; x < cbc->blocklen; x++) {
	    tmpy       = tmp[x] ^ cbc->IV[x];
	    cbc->IV[x] = ct[x];
	    pt[x]      = tmpy;
	}

	ct  += cbc->blocklen;
	pt  += cbc->blocklen;
	len -= cbc->blocklen;
    }

    return NBSCrypto_OK;
}

int cbc_done(cm_CBC *cbc)
{
    int err;

    if ((err = is_cipher_valid(cbc->cipher)) != NBSCrypto_OK) {
	return err;
    }

    cipher_descriptor[cbc->cipher].done(&cbc->cs);

    return NBSCrypto_OK;
}
