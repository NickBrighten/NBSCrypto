//
//	ccm.c
//	Authors / Developers		: Russ Housley, Doug Whiting, Niels Ferguson
//	Last Modified (Original)	: September 2003
//

#include "nbs_crypto.h"




#pragma mark - INLINE
static inline int _ccm_process(unsigned char *pt, unsigned char *ct, unsigned long len, int direction, cm_CCM *ccm)
{
    unsigned char z, b;
    unsigned long y;
    int err;

    if (ccm->aadlen != ccm->current_aadlen) {
	return NBSCrypto_ERROR;
    }

    if (ccm->ptlen < ccm->current_ptlen + len) {
	return NBSCrypto_ERROR;
    }

    ccm->current_ptlen += len;

    if (len > 0) {
	for (y = 0; y < len; y++) {
	    if (ccm->CTRlen == 16) {
		for (z = 15; z > 15-ccm->L; z--) {
		    ccm->ctr[z] = (ccm->ctr[z] + 1) & 255;
		    if (ccm->ctr[z]) break;
		}
		if ((err = cipher_descriptor[ccm->cipher].encrypt(ccm->ctr, ccm->CTRPAD, &ccm->cs)) != NBSCrypto_OK) {
		    return err;
		}
		ccm->CTRlen = 0;
	    }

	    if (direction == 1) {
		b     = pt[y];
		ct[y] = b ^ ccm->CTRPAD[ccm->CTRlen++];
	    } else {
		b     = ct[y] ^ ccm->CTRPAD[ccm->CTRlen++];
		pt[y] = b;
	    }

	    if (ccm->x == 16) {
		if ((err = cipher_descriptor[ccm->cipher].encrypt(ccm->PAD, ccm->PAD, &ccm->cs)) != NBSCrypto_OK) {
		    return err;
		}
		ccm->x = 0;
	    }
	    ccm->PAD[ccm->x++] ^= b;
	}
    }

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int ccm_add_nonce(const unsigned char *nonce, unsigned long noncelen, cm_CCM *ccm)
{
    unsigned long x, y, len;
    int err;

    ccm->noncelen = (noncelen > 13) ? 13 : noncelen;

    if ((15 - ccm->noncelen) > ccm->L) {
	ccm->L = 15 - ccm->noncelen;
    }

    if (ccm->L > 8) {
	return NBSCrypto_ERROR;
    }

    if ((ccm->noncelen + ccm->L) > 15) {
	ccm->noncelen = 15 - ccm->L;
    }

    x = 0;
    ccm->PAD[x++] = (unsigned char)(((ccm->aadlen > 0) ? (1<<6) : 0) | (((ccm->taglen - 2)>>1)<<3) | (ccm->L-1));

    for (y = 0; y < 15 - ccm->L; y++) {
	ccm->PAD[x++] = nonce[y];
    }

    len = ccm->ptlen;

    for (y = ccm->L; y < 4; y++) {
	len <<= 8;
    }

    for (y = 0; ccm->L > 4 && (ccm->L-y)>4; y++) {
	ccm->PAD[x++] = 0;
    }

    for (; y < ccm->L; y++) {
	ccm->PAD[x++] = (unsigned char)((len >> 24) & 255);
	len <<= 8;
    }

    if ((err = cipher_descriptor[ccm->cipher].encrypt(ccm->PAD, ccm->PAD, &ccm->cs)) != NBSCrypto_OK) {
	return err;
    }

    ccm->x = 0;

    if (ccm->aadlen > 0) {
	if (ccm->aadlen < ((1UL<<16) - (1UL<<8))) {
	    ccm->PAD[ccm->x++] ^= (ccm->aadlen>>8) & 255;
	    ccm->PAD[ccm->x++] ^= ccm->aadlen & 255;
	} else {
	    ccm->PAD[ccm->x++] ^= 0xFF;
	    ccm->PAD[ccm->x++] ^= 0xFE;
	    ccm->PAD[ccm->x++] ^= (ccm->aadlen>>24) & 255;
	    ccm->PAD[ccm->x++] ^= (ccm->aadlen>>16) & 255;
	    ccm->PAD[ccm->x++] ^= (ccm->aadlen>>8) & 255;
	    ccm->PAD[ccm->x++] ^= ccm->aadlen & 255;
	}
    }

    x = 0;

    ccm->ctr[x++] = (unsigned char)ccm->L-1;

    for (y = 0; y < (16 - (ccm->L+1)); ++y) {
	ccm->ctr[x++] = nonce[y];
    }

    while (x < 16) {
	ccm->ctr[x++] = 0;
    }

    ccm->CTRlen = 16;

    return NBSCrypto_OK;
}

int ccm_add_aad(const unsigned char *adata, unsigned long adatalen, cm_CCM *ccm)
{
    unsigned long y;
    int err;

    if (ccm->aadlen < ccm->current_aadlen + adatalen) {
	return NBSCrypto_ERROR;
    }

    ccm->current_aadlen += adatalen;

    for (y = 0; y < adatalen; y++) {
	if (ccm->x == 16) {
	    if ((err = cipher_descriptor[ccm->cipher].encrypt(ccm->PAD, ccm->PAD, &ccm->cs)) != NBSCrypto_OK) {
		return err;
	    }
	    ccm->x = 0;
	}
	ccm->PAD[ccm->x++] ^= adata[y];
    }

    if (ccm->aadlen == ccm->current_aadlen) {
	if (ccm->x != 0) {
	    if ((err = cipher_descriptor[ccm->cipher].encrypt(ccm->PAD, ccm->PAD, &ccm->cs)) != NBSCrypto_OK) {
		return err;
	    }
	}
	ccm->x = 0;
    }

    return NBSCrypto_OK;
}

int ccm_start(unsigned long cipher, const unsigned char *key, unsigned long keylen, unsigned long ptlen, unsigned long taglen, unsigned long aadlen, cm_CCM *ccm)
{
    int err;

    zeromem(ccm->PAD, sizeof(ccm->PAD));
    zeromem(ccm->ctr, sizeof(ccm->ctr));
    zeromem(ccm->CTRPAD, sizeof(ccm->CTRPAD));
    ccm->CTRlen = 0;
    ccm->current_ptlen = 0;
    ccm->current_aadlen = 0;

    memset(ccm, 0, sizeof(cm_CCM));

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (cipher_descriptor[cipher].block_length != 16) {
	return NBSCrypto_ERROR;
    }

    if (taglen < 4 || taglen > 16 || (taglen % 2) == 1 || aadlen < 0 || ptlen < 0) {
	return NBSCrypto_ERROR;
    }

    ccm->taglen = (int)taglen;

    if ((err = cipher_descriptor[cipher].setup(key, (int)keylen, 0, &ccm->cs)) != NBSCrypto_OK) {
	return err;
    }

    ccm->cipher = cipher;
    ccm->ptlen = ptlen;
    ccm->L   = 0;

    while (ptlen) {
	++ccm->L;
	ptlen >>= 8;
    }

    if (ccm->L <= 1) {
	ccm->L = 2;
    }

    ccm->aadlen = aadlen;

    return NBSCrypto_OK;
}

int ccm_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, cm_CCM *ccm)
{
    return _ccm_process(pt, ct, len, 1, ccm);
}

int ccm_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, cm_CCM *ccm)
{
    return _ccm_process(pt, ct, len, 0, ccm);
}

int ccm_done(unsigned char *tag, unsigned long *taglen, cm_CCM *ccm)
{
    unsigned long x, y;
    int err;

    if (ccm->ptlen != ccm->current_ptlen) {
	return NBSCrypto_ERROR;
    }

    if (ccm->x != 0) {
	if ((err = cipher_descriptor[ccm->cipher].encrypt(ccm->PAD, ccm->PAD, &ccm->cs)) != NBSCrypto_OK) {
	    return err;
	}
    }

    for (y = 15; y > 15 - ccm->L; y--) {
	ccm->ctr[y] = 0x00;
    }

    if ((err = cipher_descriptor[ccm->cipher].encrypt(ccm->ctr, ccm->CTRPAD, &ccm->cs)) != NBSCrypto_OK) {
	return err;
    }

    cipher_descriptor[ccm->cipher].done(&ccm->cs);

    for (x = 0; x < 16 && x < *taglen; x++) {
	tag[x] = ccm->PAD[x] ^ ccm->CTRPAD[x];
    }

    *taglen = x;

    return NBSCrypto_OK;
}
