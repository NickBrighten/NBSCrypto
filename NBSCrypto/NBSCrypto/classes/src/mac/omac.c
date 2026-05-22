//
//	omac.c
//

#include "nbs_crypto.h"


#define MIN(x, y) (((x)<(y))?(x):(y))


int omac_init(int cipher, const unsigned char *key, unsigned long keylen, omac_state *omac)
{
    int err, x, y, mask, msb, len;


    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    switch (cipher_descriptor[cipher].block_length) {
	case 8:{
	    mask = 0x1B;
	    len  = 8;
	    break;
	}
	case 16:{
	    mask = 0x87;
	    len  = 16;
	    break;
	}
	default:{
	    return NBSCrypto_ERROR;
	}
    }

    if ((err = cipher_descriptor[cipher].setup(key, (int)keylen, 0, &omac->cs)) != NBSCrypto_OK) {
	return err;
    }

    zeromem(omac->Lu[0], cipher_descriptor[cipher].block_length);

    if ((err = cipher_descriptor[cipher].encrypt(omac->Lu[0], omac->Lu[0], &omac->cs)) != NBSCrypto_OK) {
	return err;
    }

    for (x = 0; x < 2; x++) {
	msb = omac->Lu[x][0] >> 7;

	for (y = 0; y < (len - 1); y++) {
	    omac->Lu[x][y] = ((omac->Lu[x][y] << 1) | (omac->Lu[x][y+1] >> 7)) & 255;
	}
	omac->Lu[x][len - 1] = ((omac->Lu[x][len - 1] << 1) ^ (msb ? mask : 0)) & 255;

	if (x == 0) {
	    memcpy(omac->Lu[1], omac->Lu[0], sizeof(omac->Lu[0]));
	}
    }

    omac->cipher 	= cipher;
    omac->buflen	= 0;
    omac->block_len	= len;
    zeromem(omac->prev,  sizeof(omac->prev));
    zeromem(omac->block, sizeof(omac->block));

    return NBSCrypto_OK;
}

int omac_process(const unsigned char *in, unsigned long inlen, omac_state *omac)
{
    unsigned long n, x;
    int err;


    if ((err = is_cipher_valid(omac->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((omac->buflen > (int)sizeof(omac->block)) || (omac->buflen < 0) ||
	(omac->block_len > (int)sizeof(omac->block)) || (omac->buflen > omac->block_len)) {
	return NBSCrypto_ERROR;
    }

    while (inlen != 0) {
	if (omac->buflen == omac->block_len) {
	    for (x = 0; x < (unsigned long)omac->block_len; x++) {
		omac->block[x] ^= omac->prev[x];
	    }
	    if ((err = cipher_descriptor[omac->cipher].encrypt(omac->block, omac->prev, &omac->cs)) != NBSCrypto_OK) {
		return err;
	    }
	    omac->buflen = 0;
	}

	n = MIN(inlen, (unsigned long)(omac->block_len - omac->buflen));
	memcpy(omac->block + omac->buflen, in, n);
	omac->buflen  += n;
	inlen         -= n;
	in            += n;
    }

    return NBSCrypto_OK;
}

int omac_done(unsigned char *out, unsigned long *outlen, omac_state *omac)
{
    int err, mode;
    unsigned x;


    if ((err = is_cipher_valid(omac->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if ((omac->buflen > (int)sizeof(omac->block)) || (omac->buflen < 0) ||
	(omac->block_len > (int)sizeof(omac->block)) || (omac->buflen > omac->block_len)) {
	return NBSCrypto_ERROR;
    }

    if (omac->buflen != omac->block_len) {
	omac->block[omac->buflen++] = 0x80;

	while (omac->buflen < omac->block_len) {
	    omac->block[omac->buflen++] = 0x00;
	}
	mode = 1;
    } else {
	mode = 0;
    }

    for (x = 0; x < (unsigned)omac->block_len; x++) {
	omac->block[x] ^= omac->prev[x] ^ omac->Lu[mode][x];
    }

    if ((err = cipher_descriptor[omac->cipher].encrypt(omac->block, omac->block, &omac->cs)) != NBSCrypto_OK) {
	return err;
    }
    cipher_descriptor[omac->cipher].done(&omac->cs);

    for (x = 0; x < (unsigned)omac->block_len && x < *outlen; x++) {
	out[x] = omac->block[x];
    }
    *outlen = x;

    return NBSCrypto_OK;
}
