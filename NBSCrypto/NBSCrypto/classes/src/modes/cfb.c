//
//	cfb.c
//	Authors / Developers		: Carl M. Campbell Jr., Barrie Morgan
//	Last Modified (Original)	: February 1977
//

#include "nbs_crypto.h"




#pragma mark - FUNCTIONS
int cfb_start(unsigned long cipher, const unsigned char *iv, const unsigned char *key, int keylen, int num_rounds, cm_CFB *cfb)
{
    int x, err;

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    cfb->cipher = cipher;
    cfb->blocklen = cipher_descriptor[cipher].block_length;

    for (x = 0; x < cfb->blocklen; x++) {
	cfb->IV[x] = iv[x];
    }

    if ((err = cipher_descriptor[cipher].setup(key, keylen, num_rounds, &cfb->cs)) != NBSCrypto_OK) {
	return err;
    }

    cfb->padlen = 0;

    return cipher_descriptor[cfb->cipher].encrypt(cfb->IV, cfb->IV, &cfb->cs);
}

int cfb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_CFB *cfb)
{
    int err;

    if ((err = is_cipher_valid(cfb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (cfb->blocklen < 0 || cfb->blocklen > (int)sizeof(cfb->IV) ||
	cfb->padlen   < 0 || cfb->padlen   > (int)sizeof(cfb->pad)) {
	return NBSCrypto_ERROR;
    }

    while (len-- > 0) {
	if (cfb->padlen == cfb->blocklen) {
	    if ((err = cipher_descriptor[cfb->cipher].encrypt(cfb->pad, cfb->IV, &cfb->cs)) != NBSCrypto_OK) {
		return err;
	    }
	    cfb->padlen = 0;
	}
	cfb->pad[cfb->padlen] = (*ct = *pt ^ cfb->IV[cfb->padlen]);
	++pt;
	++ct;
	++(cfb->padlen);
    }

    return NBSCrypto_OK;
}

int cfb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_CFB *cfb)
{
    int err;

    if ((err = is_cipher_valid(cfb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (cfb->blocklen < 0 || cfb->blocklen > (int)sizeof(cfb->IV) ||
	cfb->padlen   < 0 || cfb->padlen   > (int)sizeof(cfb->pad)) {
	return NBSCrypto_ERROR;
    }

    while (len-- > 0) {
	if (cfb->padlen == cfb->blocklen) {
	    if ((err = cipher_descriptor[cfb->cipher].encrypt(cfb->pad, cfb->IV, &cfb->cs)) != NBSCrypto_OK) {
		return err;
	    }
	    cfb->padlen = 0;
	}
	cfb->pad[cfb->padlen] = *ct;
	*pt = *ct ^ cfb->IV[cfb->padlen];
	++pt;
	++ct;
	++(cfb->padlen);
    }

    return NBSCrypto_OK;
}

int cfb_done(cm_CFB *cfb)
{
    int err;

    if ((err = is_cipher_valid(cfb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    cipher_descriptor[cfb->cipher].done(&cfb->cs);

    return NBSCrypto_OK;
}
