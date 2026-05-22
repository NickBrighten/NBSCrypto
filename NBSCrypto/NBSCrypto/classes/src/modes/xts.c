//
//	xts.c
//

#include "nbs_crypto.h"


static inline void _xts_mult_x(unsigned char *I)
{
    int x;
    unsigned char t, tt = '\0';

    for (x = t = 0; x < 16; x++) {
	tt = I[x] >> 7;
	I[x] = ((I[x] << 1) | t) & 0xFF;
	t = tt;
    }

    if (tt) {
	I[0] ^= 0x87;
    }
}

static inline int _tweak_crypt(const unsigned char *P, unsigned char *C, unsigned char *T, const cm_XTS *xts)
{
    unsigned long x;
    int err;

    for (x = 0; x < 16; x++) {
	C[x] = P[x] ^ T[x];
    }

    if ((err = cipher_descriptor[xts->cipher].encrypt(C, C, &xts->cs1)) != NBSCrypto_OK) {
	return err;
    }

    for (x = 0; x < 16; x++) {
	C[x] = C[x] ^ T[x];
    }

    _xts_mult_x(T);

    return NBSCrypto_OK;
}

static inline int _tweak_uncrypt(const unsigned char *C, unsigned char *P, unsigned char *T, const cm_XTS *xts)
{
    unsigned long x;
    int err;

    for (x = 0; x < 16; x++) {
	P[x] = C[x] ^ T[x];
    }

    if ((err = cipher_descriptor[xts->cipher].decrypt(P, P, &xts->cs1)) != NBSCrypto_OK) {
	return err;
    }

    for (x = 0; x < 16; x++) {
	P[x] = P[x] ^ T[x];
    }

    _xts_mult_x(T);

    return NBSCrypto_OK;
}


int xts_start(int cipher, const unsigned char *key1, const unsigned char *key2, int keylen, int num_rounds, cm_XTS *xts)
{
    int err;

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (cipher_descriptor[cipher].block_length != 16) {
	return NBSCrypto_ERROR;
    }

    if ((err = cipher_descriptor[cipher].setup(key1, keylen, num_rounds, &xts->cs1)) != NBSCrypto_OK) {
	return err;
    }

    if ((err = cipher_descriptor[cipher].setup(key2, keylen, num_rounds, &xts->cs2)) != NBSCrypto_OK) {
	return err;
    }

    xts->cipher = cipher;

    return NBSCrypto_OK;
}

int xts_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tweak, cm_XTS *xts)
{
    unsigned char PP[16], CC[16], T[16];
    unsigned long i, m, mo, lim;
    int err;

    if ((err = is_cipher_valid(xts->cipher)) != NBSCrypto_OK) {
	return err;
    }

    m = len >> 4;
    mo = len & 15;

    if (m == 0) {
	return NBSCrypto_ERROR;
    }

    if (mo == 0) {
	lim = m;
    } else {
	lim = m - 1;
    }

    if (cipher_descriptor[xts->cipher].accel_xts_encrypt && lim > 0) {
	if ((err = cipher_descriptor[xts->cipher].accel_xts_encrypt(pt, ct, lim, tweak, &xts->cs1, &xts->cs2)) != NBSCrypto_OK) {
	    return err;
	}
	ct += lim * 16;
	pt += lim * 16;

	memcpy(T, tweak, sizeof(T));
    } else {
	if ((err = cipher_descriptor[xts->cipher].encrypt(tweak, T, &xts->cs2)) != NBSCrypto_OK) {
	    return err;
	}

	for (i = 0; i < lim; i++) {
	    if ((err = _tweak_crypt(pt, ct, T, xts)) != NBSCrypto_OK) {
		return err;
	    }
	    ct += 16;
	    pt += 16;
	}
    }

    if (mo > 0) {
	if ((err = _tweak_crypt(pt, CC, T, xts)) != NBSCrypto_OK) {
	    return err;
	}

	for (i = 0; i < mo; i++) {
	    PP[i] = pt[16 + i];
	    ct[16 + i] = CC[i];
	}

	for (; i < 16; i++) {
	    PP[i] = CC[i];
	}

	if ((err = _tweak_crypt(PP, ct, T, xts)) != NBSCrypto_OK) {
	    return err;
	}
    }

    if ((err = cipher_descriptor[xts->cipher].decrypt(T, tweak, &xts->cs2)) != NBSCrypto_OK) {
	return err;
    }

    return NBSCrypto_OK;
}

int xts_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, unsigned char *tweak, cm_XTS *xts)
{
    unsigned char PP[16], CC[16], T[16];
    unsigned long i, m, mo, lim;
    int err;

    if ((err = is_cipher_valid(xts->cipher)) != NBSCrypto_OK) {
	return err;
    }

    m = len >> 4;
    mo = len & 15;

    if (m == 0) {
	return NBSCrypto_ERROR;
    }

    if (mo == 0) {
	lim = m;
    } else {
	lim = m - 1;
    }

    if (cipher_descriptor[xts->cipher].accel_xts_decrypt && lim > 0) {
	if ((err = cipher_descriptor[xts->cipher].accel_xts_decrypt(ct, pt, lim, tweak, &xts->cs1, &xts->cs2)) != NBSCrypto_OK) {
	    return err;
	}

	ct += lim * 16;
	pt += lim * 16;

	memcpy(T, tweak, sizeof(T));
    } else {
	if ((err = cipher_descriptor[xts->cipher].encrypt(tweak, T, &xts->cs2)) != NBSCrypto_OK) {
	    return err;
	}

	for (i = 0; i < lim; i++) {
	    if ((err = _tweak_uncrypt(ct, pt, T, xts)) != NBSCrypto_OK) {
		return err;
	    }
	    ct += 16;
	    pt += 16;
	}
    }

    if (mo > 0) {
	memcpy(CC, T, 16);
	_xts_mult_x(CC);

	if ((err = _tweak_uncrypt(ct, PP, CC, xts)) != NBSCrypto_OK) {
	    return err;
	}

	for (i = 0; i < mo; i++) {
	    CC[i] = ct[16 + i];
	    pt[16 + i] = PP[i];
	}

	for (; i < 16; i++) {
	    CC[i] = PP[i];
	}

	if ((err = _tweak_uncrypt(CC, pt, T, xts)) != NBSCrypto_OK) {
	    return err;
	}
    }

    if ((err = cipher_descriptor[xts->cipher].decrypt(T, tweak, &xts->cs2)) != NBSCrypto_OK) {
	return err;
    }

    return NBSCrypto_OK;
}

int xts_done(cm_XTS *xts)
{
    cipher_descriptor[xts->cipher].done(&xts->cs1);
    cipher_descriptor[xts->cipher].done(&xts->cs2);

    return NBSCrypto_OK;
}

