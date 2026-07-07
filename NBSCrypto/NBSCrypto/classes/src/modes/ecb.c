//
//	ecb.c
//	Authors / Developers		: NIST
//	Last Modified (Original)	: 1981
//

#include "nbs_crypto.h"




#pragma mark - FUNCTIONS
int ecb_start(unsigned long cipher, const unsigned char *key, int keylen, int num_rounds, cm_ECB *ecb)
{
    int err;

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    ecb->cipher = cipher;
    ecb->blocklen = cipher_descriptor[cipher].block_length;

    return cipher_descriptor[cipher].setup(key, keylen, num_rounds, &ecb->cs);
}

int ecb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_ECB *ecb)
{
    int err;

    if ((err = is_cipher_valid(ecb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (len % cipher_descriptor[ecb->cipher].block_length) {
	return NBSCrypto_ERROR;
    }

    if (cipher_descriptor[ecb->cipher].accel_ecb_encrypt != NULL) {
	return cipher_descriptor[ecb->cipher].accel_ecb_encrypt(pt, ct, len / cipher_descriptor[ecb->cipher].block_length, &ecb->cs);
    }

    while (len) {
	if ((err = cipher_descriptor[ecb->cipher].encrypt(pt, ct, &ecb->cs)) != NBSCrypto_OK) {
	    return err;
	}
	pt  += cipher_descriptor[ecb->cipher].block_length;
	ct  += cipher_descriptor[ecb->cipher].block_length;
	len -= cipher_descriptor[ecb->cipher].block_length;
    }

    return NBSCrypto_OK;
}

int ecb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_ECB *ecb)
{
    int err;

    if ((err = is_cipher_valid(ecb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (len % cipher_descriptor[ecb->cipher].block_length) {
	return NBSCrypto_ERROR;
    }

    if (cipher_descriptor[ecb->cipher].accel_ecb_decrypt != NULL) {
	return cipher_descriptor[ecb->cipher].accel_ecb_decrypt(ct, pt, len / cipher_descriptor[ecb->cipher].block_length, &ecb->cs);
    }

    while (len) {
	if ((err = cipher_descriptor[ecb->cipher].decrypt(ct, pt, &ecb->cs)) != NBSCrypto_OK) {
	    return err;
	}
	pt  += cipher_descriptor[ecb->cipher].block_length;
	ct  += cipher_descriptor[ecb->cipher].block_length;
	len -= cipher_descriptor[ecb->cipher].block_length;
    }

    return NBSCrypto_OK;
}

int ecb_done(cm_ECB *ecb)
{
    int err;

    if ((err = is_cipher_valid(ecb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    cipher_descriptor[ecb->cipher].done(&ecb->cs);

    return NBSCrypto_OK;
}
