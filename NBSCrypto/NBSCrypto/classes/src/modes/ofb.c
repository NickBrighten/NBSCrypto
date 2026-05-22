//
//	ofb.c
//

#include "nbs_crypto.h"


int ofb_start(int cipher, const unsigned char *iv, const unsigned char *key, int keylen, int num_rounds, cm_OFB *ofb)
{
    int x, err;

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    ofb->cipher = cipher;
    ofb->blocklen = cipher_descriptor[cipher].block_length;

    for (x = 0; x < ofb->blocklen; x++) {
	ofb->IV[x] = iv[x];
    }

    ofb->padlen = ofb->blocklen;

    return cipher_descriptor[cipher].setup(key, keylen, num_rounds, &ofb->cs);
}

int ofb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_OFB *ofb)
{
    int err;

    if ((err = is_cipher_valid(ofb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (ofb->blocklen < 0 || ofb->blocklen > (int)sizeof(ofb->IV) ||
	ofb->padlen   < 0 || ofb->padlen   > (int)sizeof(ofb->IV)) {
	return NBSCrypto_ERROR;
    }

    while (len-- > 0) {
	if (ofb->padlen == ofb->blocklen) {
	    if ((err = cipher_descriptor[ofb->cipher].encrypt(ofb->IV, ofb->IV, &ofb->cs)) != NBSCrypto_OK) {
		return err;
	    }
	    ofb->padlen = 0;
	}
	*ct++ = *pt++ ^ ofb->IV[(ofb->padlen)++];
    }

    return NBSCrypto_OK;
}

int ofb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_OFB *ofb)
{
    return ofb_encrypt(ct, pt, len, ofb);
}

int ofb_done(cm_OFB *ofb)
{
    int err;

    if ((err = is_cipher_valid(ofb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    cipher_descriptor[ofb->cipher].done(&ofb->cs);

    return NBSCrypto_OK;
}
