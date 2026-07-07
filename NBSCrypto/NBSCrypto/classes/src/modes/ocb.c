//
//	ocb.c
//	Authors / Developers		: Phillip Rogaway, Mihir Bellare, John Black, Ted Krovetz
//	Last Modified (Original)	: 2001
//

#include "nbs_crypto.h"




#pragma mark - DEFINES
static const struct {
    int len;
    unsigned char poly_div[MAXBLOCKSIZE],
    poly_mul[MAXBLOCKSIZE];
} polys[] = {
    {
	8,
	{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D },
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B }
    }, {
	16,
	{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43 },
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 }
    }
};




#pragma mark - INLINE
static inline int _ocb_ntz(unsigned long x)
{
    int c;
    x &= 0xFFFFFFFFUL;
    c = 0;
    while ((x & 1) == 0) {
	++c;
	x >>= 1;
    }
    return c;
}

static inline void _ocb_shift_xor(cm_OCB *ocb, unsigned char *Z)
{
    int x, y;
    y = _ocb_ntz(ocb->block_index++);
    for (x = 0; x < ocb->block_len; x++) {
	ocb->Li[x] ^= ocb->Ls[y][x];
	Z[x]        = ocb->Li[x] ^ ocb->R[x];
    }
}

static inline int _ocb_done(cm_OCB *ocb, const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tag, unsigned long *taglen, int mode)
{
    unsigned char *Z, *Y, *X;
    int err, x;

    if ((err = is_cipher_valid(ocb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length || (int)len > ocb->block_len || (int)len < 0) {
	return NBSCrypto_ERROR;
    }

    Z = malloc(MAXBLOCKSIZE);
    Y = malloc(MAXBLOCKSIZE);
    X = malloc(MAXBLOCKSIZE);

    if (X == NULL || Y == NULL || Z == NULL) {
	if (X != NULL) {
	    free(X);
	}
	if (Y != NULL) {
	    free(Y);
	}
	if (Z != NULL) {
	    free(Z);
	}
	return NBSCrypto_ERROR;
    }

    _ocb_shift_xor(ocb, X);
    memcpy(Z, X, ocb->block_len);

    X[ocb->block_len-1] ^= (len*8)&255;
    X[ocb->block_len-2] ^= ((len*8)>>8)&255;
    for (x = 0; x < ocb->block_len; x++) {
	X[x] ^= ocb->Lr[x];
    }

    if ((err = cipher_descriptor[ocb->cipher].encrypt(X, Y, &ocb->cs)) != NBSCrypto_OK) {
	goto ERR;
    }

    if (mode == 1) {
	for (x = 0; x < (int)len; x++) {
	    ocb->checksum[x] ^= ct[x];
	}
    }

    for (x = 0; x < (int)len; x++) {
	ct[x] = pt[x] ^ Y[x];
    }

    if (mode == 0) {
	for (x = 0; x < (int)len; x++) {
	    ocb->checksum[x] ^= ct[x];
	}
    }

    for (x = 0; x < ocb->block_len; x++) {
	ocb->checksum[x] ^= Y[x] ^ Z[x];
    }

    if ((err = cipher_descriptor[ocb->cipher].encrypt(ocb->checksum, X, &ocb->cs)) != NBSCrypto_OK) {
	goto ERR;
    }

    cipher_descriptor[ocb->cipher].done(&ocb->cs);

    for (x = 0; x < ocb->block_len && x < (int)*taglen; x++) {
	tag[x] = X[x];
    }
    *taglen = x;

ERR:
    free(X);
    free(Y);
    free(Z);

    return err;
}




#pragma mark - FUNCTIONS
int ocb_start(unsigned long cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce, cm_OCB *ocb)
{
    int poly, x, y, m, err;

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    ocb->block_len = cipher_descriptor[cipher].block_length;

    x = (int)(sizeof(polys)/sizeof(polys[0]));
    for (poly = 0; poly < x; poly++) {
	if (polys[poly].len == ocb->block_len) {
	    break;
	}
    }
    if (poly == x) {
	return NBSCrypto_ERROR;
    }

    if (polys[poly].len != ocb->block_len) {
	return NBSCrypto_ERROR;
    }

    if ((err = cipher_descriptor[cipher].setup(key, (int)keylen, 0, &ocb->cs)) != NBSCrypto_OK) {
	return err;
    }

    zeromem(ocb->L, ocb->block_len);

    if ((err = cipher_descriptor[cipher].encrypt(ocb->L, ocb->L, &ocb->cs)) != NBSCrypto_OK) {
	return err;
    }

    for (x = 0; x < ocb->block_len; x++) {
	ocb->R[x] = ocb->L[x] ^ nonce[x];
    }

    if ((err = cipher_descriptor[cipher].encrypt(ocb->R, ocb->R, &ocb->cs)) != NBSCrypto_OK) {
	return err;
    }

    memcpy(ocb->Ls[0], ocb->L, ocb->block_len);

    for (x = 1; x < 32; x++) {
	m = ocb->Ls[x-1][0] >> 7;
	for (y = 0; y < ocb->block_len-1; y++) {
	    ocb->Ls[x][y] = ((ocb->Ls[x-1][y] << 1) | (ocb->Ls[x-1][y+1] >> 7)) & 255;
	}
	ocb->Ls[x][ocb->block_len-1] = (ocb->Ls[x-1][ocb->block_len-1] << 1) & 255;

	if (m == 1) {
	    for (y = 0; y < ocb->block_len; y++) {
		ocb->Ls[x][y] ^= polys[poly].poly_mul[y];
	    }
	}
    }

    m = ocb->L[ocb->block_len-1] & 1;

    for (x = ocb->block_len - 1; x > 0; x--) {
	ocb->Lr[x] = ((ocb->L[x] >> 1) | (ocb->L[x-1] << 7)) & 255;
    }
    ocb->Lr[0] = ocb->L[0] >> 1;

    if (m == 1) {
	for (x = 0; x < ocb->block_len; x++) {
	    ocb->Lr[x] ^= polys[poly].poly_div[x];
	}
    }

    zeromem(ocb->Li,       ocb->block_len);
    zeromem(ocb->checksum, ocb->block_len);

    ocb->block_index = 1;
    ocb->cipher      = cipher;

    return NBSCrypto_OK;
}

int ocb_encrypt(const unsigned char *pt, unsigned char *ct, cm_OCB *ocb)
{
    unsigned char Z[MAXBLOCKSIZE], tmp[MAXBLOCKSIZE];
    int err, x;

    if ((err = is_cipher_valid(ocb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length) {
	return NBSCrypto_ERROR;
    }

    for (x = 0; x < ocb->block_len; x++) {
	ocb->checksum[x] ^= pt[x];
    }

    _ocb_shift_xor(ocb, Z);

    for (x = 0; x < ocb->block_len; x++) {
	tmp[x] = pt[x] ^ Z[x];
    }

    if ((err = cipher_descriptor[ocb->cipher].encrypt(tmp, ct, &ocb->cs)) != NBSCrypto_OK) {
	return err;
    }

    for (x = 0; x < ocb->block_len; x++) {
	ct[x] ^= Z[x];
    }

    return NBSCrypto_OK;
}

int ocb_decrypt(const unsigned char *ct, unsigned char *pt, cm_OCB *ocb)
{
    unsigned char Z[MAXBLOCKSIZE], tmp[MAXBLOCKSIZE];
    int err, x;


    if ((err = is_cipher_valid(ocb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length) {
	return NBSCrypto_ERROR;
    }

    _ocb_shift_xor(ocb, Z);

    for (x = 0; x < ocb->block_len; x++) {
	tmp[x] = ct[x] ^ Z[x];
    }

    if ((err = cipher_descriptor[ocb->cipher].decrypt(tmp, pt, &ocb->cs)) != NBSCrypto_OK) {
	return err;
    }

    for (x = 0; x < ocb->block_len; x++) {
	pt[x] ^= Z[x];
    }

    for (x = 0; x < ocb->block_len; x++) {
	ocb->checksum[x] ^= pt[x];
    }

    return NBSCrypto_OK;
}

int ocb_done(const unsigned char *in, unsigned char *out, unsigned long len, unsigned char *tag, unsigned long *taglen, int mode, cm_OCB *ocb)
{
    int r=0;
    switch (mode) {
	case 0:{
	    r = _ocb_done(ocb, in, out, len, tag, taglen, 0);
	    break;
	}
	case 1:{
	    r = _ocb_done(ocb, in, out, len, tag, taglen, 1);
	    break;
	}
    }
    return r;
}
