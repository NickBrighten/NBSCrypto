//
//	pmac.c
//

#include "nbs_crypto.h"


#define MIN(x, y) (((x)<(y))?(x):(y))


static const struct {
    int len;
    unsigned char poly_div[MAXBLOCKSIZE], poly_mul[MAXBLOCKSIZE];
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


static inline int _ntz(unsigned long x)
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

static inline void _shift_xor(pmac_state *pmac)
{
    int x, y;
    y = _ntz(pmac->block_index++);
    for (x = 0; x < pmac->block_len; x++) {
	pmac->Li[x] ^= pmac->Ls[y][x];
    }
}

int pmac_init(int cipher, const unsigned char *key, unsigned long keylen, pmac_state *pmac)
{
    int poly, x, y, m, err;
    unsigned char *L;


    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    pmac->block_len = cipher_descriptor[cipher].block_length;
    for (poly = 0; poly < (int)(sizeof(polys)/sizeof(polys[0])); poly++) {
	if (polys[poly].len == pmac->block_len) {
	    break;
	}
    }

    if (poly >= (int)(sizeof(polys)/sizeof(polys[0]))) {
	return NBSCrypto_ERROR;
    }

    if (polys[poly].len != pmac->block_len) {
	return NBSCrypto_ERROR;
    }

    if ((err = cipher_descriptor[cipher].setup(key, (int)keylen, 0, &pmac->cs)) != NBSCrypto_OK) {
	return err;
    }

    L = malloc(pmac->block_len);

    if (L == NULL) {
	return NBSCrypto_ERROR;
    }

    zeromem(L, pmac->block_len);

    if ((err = cipher_descriptor[cipher].encrypt(L, L, &pmac->cs)) != NBSCrypto_OK) {
	goto error;
    }

    memcpy(pmac->Ls[0], L, pmac->block_len);

    for (x = 1; x < 32; x++) {
	m = pmac->Ls[x-1][0] >> 7;
	for (y = 0; y < pmac->block_len-1; y++) {
	    pmac->Ls[x][y] = ((pmac->Ls[x-1][y] << 1) | (pmac->Ls[x-1][y+1] >> 7)) & 255;
	}

	pmac->Ls[x][pmac->block_len-1] = (pmac->Ls[x-1][pmac->block_len-1] << 1) & 255;

	if (m == 1) {
	    for (y = 0; y < pmac->block_len; y++) {
		pmac->Ls[x][y] ^= polys[poly].poly_mul[y];
	    }
	}
    }

    m = L[pmac->block_len-1] & 1;

    for (x = pmac->block_len - 1; x > 0; x--) {
	pmac->Lr[x] = ((L[x] >> 1) | (L[x-1] << 7)) & 255;
    }

    pmac->Lr[0] = L[0] >> 1;

    if (m == 1) {
	for (x = 0; x < pmac->block_len; x++) {
	    pmac->Lr[x] ^= polys[poly].poly_div[x];
	}
    }

    pmac->block_index = 1;
    pmac->cipher  = cipher;
    pmac->buflen      = 0;
    zeromem(pmac->block,    sizeof(pmac->block));
    zeromem(pmac->Li,       sizeof(pmac->Li));
    zeromem(pmac->checksum, sizeof(pmac->checksum));
    err = NBSCrypto_OK;
error:
    free(L);

    return err;
}

int pmac_process(const unsigned char *in, unsigned long inlen, pmac_state *pmac)
{
    int err, n;
    unsigned long x;
    unsigned char Z[MAXBLOCKSIZE];


    if ((err = is_cipher_valid(pmac->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((pmac->buflen > (int)sizeof(pmac->block)) || (pmac->buflen < 0) ||
	(pmac->block_len > (int)sizeof(pmac->block)) || (pmac->buflen > pmac->block_len)) {
	return NBSCrypto_ERROR;
    }

    while (inlen != 0) {
	if (pmac->buflen == pmac->block_len) {
	    _shift_xor(pmac);
	    for (x = 0; x < (unsigned long)pmac->block_len; x++) {
		Z[x] = pmac->Li[x] ^ pmac->block[x];
	    }
	    if ((err = cipher_descriptor[pmac->cipher].encrypt(Z, Z, &pmac->cs)) != NBSCrypto_OK) {
		return err;
	    }
	    for (x = 0; x < (unsigned long)pmac->block_len; x++) {
		pmac->checksum[x] ^= Z[x];
	    }
	    pmac->buflen = 0;
	}

	n = MIN((int)inlen, (int)(pmac->block_len - pmac->buflen));
	memcpy(pmac->block + pmac->buflen, in, n);
	pmac->buflen  += n;
	inlen         -= n;
	in            += n;
    }

    return NBSCrypto_OK;
}

int pmac_done(unsigned char *out, unsigned long *outlen, pmac_state *pmac)
{
    int err, x;

    if ((err = is_cipher_valid(pmac->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((pmac->buflen > (int)sizeof(pmac->block)) || (pmac->buflen < 0) ||
	(pmac->block_len > (int)sizeof(pmac->block)) || (pmac->buflen > pmac->block_len)) {
	return NBSCrypto_ERROR;
    }

    if (pmac->buflen == pmac->block_len) {
	for (x = 0; x < pmac->block_len; x++) {
	    pmac->checksum[x] ^= pmac->block[x] ^ pmac->Lr[x];
	}
    } else {
	for (x = 0; x < pmac->buflen; x++) {
	    pmac->checksum[x] ^= pmac->block[x];
	}
	pmac->checksum[x] ^= 0x80;
    }

    if ((err = cipher_descriptor[pmac->cipher].encrypt(pmac->checksum, pmac->checksum, &pmac->cs)) != NBSCrypto_OK) {
	return err;
    }
    cipher_descriptor[pmac->cipher].done(&pmac->cs);

    for (x = 0; x < pmac->block_len && x < (int)*outlen; x++) {
	out[x] = pmac->checksum[x];
    }
    *outlen = x;

    return NBSCrypto_OK;
}
