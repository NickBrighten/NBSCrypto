//
//	ctr.c
//

#include "nbs_crypto.h"


static inline int _ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_CTR *ctr)
{
    int x, err;

    while (len) {
	if (ctr->padlen == ctr->blocklen) {
	    if (ctr->mode == CTR_COUNTER_LITTLE_ENDIAN) {
		for (x = 0; x < ctr->ctrlen; x++) {
		    ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
		    if (ctr->ctr[x] != (unsigned char)0) {
			break;
		    }
		}
	    } else {
		for (x = ctr->blocklen-1; x >= ctr->ctrlen; x--) {
		    ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
		    if (ctr->ctr[x] != (unsigned char)0) {
			break;
		    }
		}
	    }

	    if ((err = cipher_descriptor[ctr->cipher].encrypt(ctr->ctr, ctr->pad, &ctr->cs)) != NBSCrypto_OK) {
		return err;
	    }
	    ctr->padlen = 0;
	}
	*ct++ = *pt++ ^ ctr->pad[ctr->padlen++];
	--len;
    }

    return NBSCrypto_OK;
}

int ctr_start(int cipher, const unsigned char *iv, const unsigned char *key, int keylen, int num_rounds, int ctr_mode, cm_CTR *ctr)
{
    int x, err;

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    ctr->ctrlen = (ctr_mode & 255) ? (ctr_mode & 255) : cipher_descriptor[cipher].block_length;

    if (ctr->ctrlen > cipher_descriptor[cipher].block_length) {
	return NBSCrypto_ERROR;
    }

    if ((ctr_mode & 0x1000) == CTR_COUNTER_BIG_ENDIAN) {
	ctr->ctrlen = cipher_descriptor[cipher].block_length - ctr->ctrlen;
    }

    if ((err = cipher_descriptor[cipher].setup(key, keylen, num_rounds, &ctr->cs)) != NBSCrypto_OK) {
	return err;
    }

    ctr->blocklen = cipher_descriptor[cipher].block_length;
    ctr->cipher   = cipher;
    ctr->padlen   = 0;
    ctr->mode     = ctr_mode & 0x1000;

    for (x = 0; x < ctr->blocklen; x++) {
	ctr->ctr[x] = iv[x];
    }

    if (ctr_mode & CTR_RFC3686) {
	if (ctr->mode == CTR_COUNTER_LITTLE_ENDIAN) {
	    for (x = 0; x < ctr->ctrlen; x++) {
		ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
		if (ctr->ctr[x] != (unsigned char)0) {
		    break;
		}
	    }
	} else {
	    for (x = ctr->blocklen-1; x >= ctr->ctrlen; x--) {
		ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
		if (ctr->ctr[x] != (unsigned char)0) {
		    break;
		}
	    }
	}
    }

    return cipher_descriptor[ctr->cipher].encrypt(ctr->ctr, ctr->pad, &ctr->cs);
}

int ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_CTR *ctr)
{
    int err, fr;

    if ((err = is_cipher_valid(ctr->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((ctr->blocklen < 1) || (ctr->blocklen > (int)sizeof(ctr->ctr)) ||
	(ctr->padlen   < 0) || (ctr->padlen   > (int)sizeof(ctr->pad))) {
	return NBSCrypto_ERROR;
    }

    if ((cipher_descriptor[ctr->cipher].accel_ctr_encrypt != NULL) && (len >= (unsigned long)ctr->blocklen)) {
	if (ctr->padlen < ctr->blocklen) {
	    fr = ctr->blocklen - ctr->padlen;
	    if ((err = _ctr_encrypt(pt, ct, fr, ctr)) != NBSCrypto_OK) {
		return err;
	    }
	    pt += fr;
	    ct += fr;
	    len -= fr;
	}

	if (len >= (unsigned long)ctr->blocklen) {
	    if ((err = cipher_descriptor[ctr->cipher].accel_ctr_encrypt(pt, ct, len/ctr->blocklen, ctr->ctr, ctr->mode, &ctr->cs)) != NBSCrypto_OK) {
		return err;
	    }
	    pt += (len / ctr->blocklen) * ctr->blocklen;
	    ct += (len / ctr->blocklen) * ctr->blocklen;
	    len %= ctr->blocklen;
	}
    }

    return _ctr_encrypt(pt, ct, len, ctr);
}

int ctr_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_CTR *ctr)
{
    return ctr_encrypt(ct, pt, len, ctr);
}

int ctr_done(cm_CTR *ctr)
{
    int err;

    if ((err = is_cipher_valid(ctr->cipher)) != NBSCrypto_OK) {
	return err;
    }

    cipher_descriptor[ctr->cipher].done(&ctr->cs);

    return NBSCrypto_OK;
}
