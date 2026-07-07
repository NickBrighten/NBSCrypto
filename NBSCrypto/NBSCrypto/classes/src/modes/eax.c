//
//	eax.c
//	Authors / Developers		: Mihir Bellare, Phillip Rogaway, David Wagner
//	Last Modified (Original)	: April 2003
//

#include "nbs_crypto.h"




#pragma mark - FUNCTIONS
int eax_start(unsigned long cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *header, unsigned long headerlen, cm_EAX *eax)
{
    int err, blklen;
    unsigned char *buf;
    unsigned long len;
    omac_state *omac;


    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }
    blklen = cipher_descriptor[cipher].block_length;

    buf  = malloc(MAXBLOCKSIZE);
    omac = malloc(sizeof(*omac));

    if (buf == NULL || omac == NULL) {
	if (buf != NULL) {
	    free(buf);
	}
	if (omac != NULL) {
	    free(omac);
	}
	return NBSCrypto_ERROR;
    }

    zeromem(buf, MAXBLOCKSIZE);

    if ((err = omac_init(cipher, key, keylen, omac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    if ((err = omac_process(buf, blklen, omac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    if ((err = omac_process(nonce, noncelen, omac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    len = sizeof(eax->N);
    if ((err = omac_done(eax->N, &len, omac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    zeromem(buf, MAXBLOCKSIZE);

    buf[blklen - 1] = 1;

    if ((err = omac_init(cipher, key, keylen, &eax->headeromac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    if ((err = omac_process(buf, blklen, &eax->headeromac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    if (headerlen != 0) {
	if ((err = omac_process(header, headerlen, &eax->headeromac)) != NBSCrypto_OK) {
	    goto _ERR;
	}
    }

    if ((err = ctr_start(cipher, eax->N, key, (int)keylen, 0, CTR_COUNTER_BIG_ENDIAN, &eax->ctr)) != NBSCrypto_OK) {
	goto _ERR;
    }

    if ((err = omac_init(cipher, key, keylen, &eax->ctomac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    zeromem(buf, MAXBLOCKSIZE);

    buf[blklen-1] = 2;

    if ((err = omac_process(buf, blklen, &eax->ctomac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    err = NBSCrypto_OK;

_ERR:
    free(omac);
    free(buf);

    return err;
}

int eax_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_EAX *eax)
{
    int err;


    if ((err = ctr_encrypt(pt, ct, len, &eax->ctr)) != NBSCrypto_OK) {
	return err;
    }

    return omac_process(ct, len, &eax->ctomac);
}

int eax_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_EAX *eax)
{
    int err;


    if ((err = omac_process(ct, len, &eax->ctomac)) != NBSCrypto_OK) {
	return err;
    }

    return ctr_decrypt(ct, pt, len, &eax->ctr);
}

int eax_done(unsigned char *tag, unsigned long *taglen, cm_EAX *eax)
{
    int err;
    unsigned char *headermac, *ctomac;
    unsigned long x, len;


    headermac = malloc(MAXBLOCKSIZE);
    ctomac    = malloc(MAXBLOCKSIZE);

    if (headermac == NULL || ctomac == NULL) {
	if (headermac != NULL) {
	    free(headermac);
	}
	if (ctomac != NULL) {
	    free(ctomac);
	}
	return NBSCrypto_ERROR;
    }

    len = MAXBLOCKSIZE;
    if ((err = omac_done(ctomac, &len, &eax->ctomac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    if ((err = omac_done(headermac, &len, &eax->headeromac)) != NBSCrypto_OK) {
	goto _ERR;
    }

    if ((err = ctr_done(&eax->ctr)) != NBSCrypto_OK) {
	goto _ERR;
    }

    for (x = 0; x < len && x < *taglen; x++) {
	tag[x] = eax->N[x] ^ headermac[x] ^ ctomac[x];
    }
    *taglen = x;

    err = NBSCrypto_OK;

_ERR:
    free(ctomac);
    free(headermac);

    return err;
}
