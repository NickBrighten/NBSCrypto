//
//	f8.c
//

#include "nbs_crypto.h"


#define STORE32H(x, y)					\
    do {						\
	(y)[0] = (unsigned char)(((x)>>24)&255);	\
	(y)[1] = (unsigned char)(((x)>>16)&255);	\
	(y)[2] = (unsigned char)(((x)>>8)&255);		\
	(y)[3] = (unsigned char)((x)&255);		\
} while(0)


int f8_start(int cipher, const unsigned char *iv, const unsigned char *key, int keylen, const unsigned char *salt_key, int skeylen, int num_rounds, cm_F8 *f8)
{
    int x, err;
    unsigned char tkey[MAXBLOCKSIZE];

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    f8->blockcnt = 0;
    f8->cipher   = cipher;
    f8->blocklen = cipher_descriptor[cipher].block_length;
    f8->padlen   = f8->blocklen;

    zeromem(tkey, sizeof(tkey));

    for (x = 0; x < keylen && x < (int)sizeof(tkey); x++) {
	tkey[x] = key[x];
    }

    for (x = 0; x < skeylen && x < (int)sizeof(tkey); x++) {
	tkey[x] ^= salt_key[x];
    }

    for (; x < keylen && x < (int)sizeof(tkey); x++) {
	tkey[x] ^= 0x55;
    }

    if ((err = cipher_descriptor[cipher].setup(tkey, keylen, num_rounds, &f8->cs)) != NBSCrypto_OK) {
	return err;
    }

    if ((err = cipher_descriptor[f8->cipher].encrypt(iv, f8->MIV, &f8->cs)) != NBSCrypto_OK) {
	cipher_descriptor[f8->cipher].done(&f8->cs);
	return err;
    }

    zeromem(tkey, sizeof(tkey));
    zeromem(f8->IV, sizeof(f8->IV));

    cipher_descriptor[f8->cipher].done(&f8->cs);

    return cipher_descriptor[cipher].setup(key, keylen, num_rounds, &f8->cs);
}

int f8_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_F8 *f8)
{
    int err, x;
    unsigned char buf[MAXBLOCKSIZE];

    if ((err = is_cipher_valid(f8->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (f8->blocklen < 0 || f8->blocklen > (int)sizeof(f8->IV) ||
	f8->padlen   < 0 || f8->padlen   > (int)sizeof(f8->IV)) {
	return NBSCrypto_ERROR;
    }

    zeromem(buf, sizeof(buf));

    if (f8->padlen == f8->blocklen) {
	STORE32H(f8->blockcnt, (buf+(f8->blocklen-4)));
	++(f8->blockcnt);
	for (x = 0; x < f8->blocklen; x++) {
	    f8->IV[x] ^= f8->MIV[x] ^ buf[x];
	}
	if ((err = cipher_descriptor[f8->cipher].encrypt(f8->IV, f8->IV, &f8->cs)) != NBSCrypto_OK) {
	    return err;
	}
	f8->padlen = 0;
    }

    while (len > 0) {
	if (f8->padlen == f8->blocklen) {
	    STORE32H(f8->blockcnt, (buf+(f8->blocklen-4)));
	    ++(f8->blockcnt);
	    for (x = 0; x < f8->blocklen; x++) {
		f8->IV[x] ^= f8->MIV[x] ^ buf[x];
	    }
	    if ((err = cipher_descriptor[f8->cipher].encrypt(f8->IV, f8->IV, &f8->cs)) != NBSCrypto_OK) {
		return err;
	    }
	    f8->padlen = 0;
	}
	*ct++ = *pt++ ^ f8->IV[f8->padlen++];
	--len;
    }
    return NBSCrypto_OK;
}

int f8_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_F8 *f8)
{
    return f8_encrypt(ct, pt, len, f8);
}

int f8_done(cm_F8 *f8)
{
    int err;

    if ((err = is_cipher_valid(f8->cipher)) != NBSCrypto_OK) {
	return err;
    }

    cipher_descriptor[f8->cipher].done(&f8->cs);

    return NBSCrypto_OK;
}
