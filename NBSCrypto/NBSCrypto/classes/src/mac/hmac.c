//
//	hmac.c
//

#include "nbs_crypto.h"


static inline int _hash_memory(int hash, const unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen)
{
    hash_state *hs;
    int err;

    if ((err = is_hash_valid(hash)) != NBSCrypto_OK) {
	return err;
    }

    if (*outlen < hash_descriptor[hash].hashsize) {
	*outlen = hash_descriptor[hash].hashsize;
	return NBSCrypto_ERROR;
    }

    hs = malloc(sizeof(hash_state));
    if (hs == NULL) {
	return NBSCrypto_OK;
    }

    if ((err = hash_descriptor[hash].init(hs)) != NBSCrypto_OK) {
	goto ERR;
    }
    if ((err = hash_descriptor[hash].process(hs, in, inlen)) != NBSCrypto_OK) {
	goto ERR;
    }
    err = hash_descriptor[hash].done(hs, out);
    *outlen = hash_descriptor[hash].hashsize;

ERR:
    free(hs);

    return err;
}

int hmac_init(int hash, const unsigned char *key, unsigned long keylen, hmac_state *hmac)
{
    unsigned char *buf;
    unsigned long hashsize;
    unsigned long i, z;
    int err;

    if ((err = is_hash_valid(hash)) != NBSCrypto_OK) {
	return err;
    }

    hmac->hash = hash;
    hashsize   = hash_descriptor[hash].hashsize;

    if (keylen == 0) {
	return NBSCrypto_ERROR;
    }

    buf = malloc(hash_descriptor[hash].blocksize);
    if (buf == NULL) {
	return NBSCrypto_OK;
    }

    if (sizeof(hmac->key) < hash_descriptor[hash].blocksize) {
	err = NBSCrypto_ERROR;
	goto ERR;
    }

    if(keylen > hash_descriptor[hash].blocksize) {
	z = hash_descriptor[hash].blocksize;
	if ((err = _hash_memory(hash, key, keylen, hmac->key, &z)) != NBSCrypto_OK) {
	    goto ERR;
	}
	keylen = hashsize;
    } else {
	memcpy(hmac->key, key, (size_t)keylen);
    }

    if(keylen < hash_descriptor[hash].blocksize) {
	zeromem((hmac->key) + keylen, (size_t)((hash_descriptor[hash].blocksize) - keylen));
    }

    for(i=0; i < hash_descriptor[hash].blocksize;   i++) {
	buf[i] = hmac->key[i] ^ 0x36;
    }

    if ((err = hash_descriptor[hash].init(&hmac->hs)) != NBSCrypto_OK) {
	goto ERR;
    }

    if ((err = hash_descriptor[hash].process(&hmac->hs, buf, hash_descriptor[hash].blocksize)) != NBSCrypto_OK) {
	goto ERR;
    }


ERR:
    free(buf);

    return err;
}

int hmac_process(const unsigned char *in, unsigned long inlen, hmac_state *hmac)
{
    int err;

    if ((err = is_hash_valid(hmac->hash)) != NBSCrypto_OK) {
	return err;
    }
    return hash_descriptor[hmac->hash].process(&hmac->hs, in, inlen);
}

int hmac_done(unsigned char *out, unsigned long *outlen, hmac_state *hmac)
{
    unsigned char *buf, *isha;
    unsigned long hashsize, i;
    int hash, err;


    hash = hmac->hash;
    if((err = is_hash_valid(hash)) != NBSCrypto_OK) {
	return err;
    }

    hashsize = hash_descriptor[hash].hashsize;

    buf  = malloc(hash_descriptor[hash].blocksize);
    isha = malloc(hashsize);

    if (buf == NULL || isha == NULL) {
	if (buf != NULL) {
	    free(buf);
	}
	if (isha != NULL) {
	    free(isha);
	}
	return NBSCrypto_ERROR;
    }

    if ((err = hash_descriptor[hash].done(&hmac->hs, isha)) != NBSCrypto_OK) {
	goto ERR;
    }

    for(i=0; i < hash_descriptor[hash].blocksize; i++) {
	buf[i] = hmac->key[i] ^ 0x5C;
    }

    if ((err = hash_descriptor[hash].init(&hmac->hs)) != NBSCrypto_OK) {
	goto ERR;
    }
    if ((err = hash_descriptor[hash].process(&hmac->hs, buf, hash_descriptor[hash].blocksize)) != NBSCrypto_OK) {
	goto ERR;
    }
    if ((err = hash_descriptor[hash].process(&hmac->hs, isha, hashsize)) != NBSCrypto_OK) {
	goto ERR;
    }
    if ((err = hash_descriptor[hash].done(&hmac->hs, buf)) != NBSCrypto_OK) {
	goto ERR;
    }

    for (i = 0; i < hashsize && i < *outlen; i++) {
	out[i] = buf[i];
    }
    *outlen = i;

    err = NBSCrypto_OK;

ERR:
    free(isha);
    free(buf);

    return err;
}
