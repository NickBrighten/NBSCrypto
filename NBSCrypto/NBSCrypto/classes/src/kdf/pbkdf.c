//
//	pbkdf.c
//	Authors / Developers		: Burt Kaliski
//	Last Modified (Original)	: 2017 (2000)
//

#include "nbs_crypto.h"




#define STORE32BE(a, p)						\
    ((unsigned char *)(p))[0] = ((unsigned)(a) >> 24) & 0xFFU,	\
    ((unsigned char *)(p))[1] = ((unsigned)(a) >> 16) & 0xFFU,	\
    ((unsigned char *)(p))[2] = ((unsigned)(a) >>  8) & 0xFFU,	\
    ((unsigned char *)(p))[3] = ((unsigned)(a) >>  0) & 0xFFU

#define MIN(a, b)   ((a) < (b) ? (a) : (b))

//const unsigned char PBKDF2_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C};


int pbkdf1(unsigned long hash, const unsigned char *key, unsigned long keylen, const unsigned char *salt, unsigned long saltlen, int c, unsigned char *out, unsigned long outlen)
{
    int i;
    int err;

    if ((err = is_hash_valid(hash)) != NBSCrypto_OK) {
	return err;
    }

    if(key == NULL || salt == NULL || out == NULL){
	return NBSCrypto_ERROR;
    }

    if(c < 1){
	return NBSCrypto_ERROR;
    }

    if(outlen > hash_descriptor[hash].hashsize){
	return NBSCrypto_ERROR;
    }

    unsigned char t[hash_descriptor[hash].hashsize];
    hash_state *hs;

    hs = malloc(sizeof(hash_state));
    if(hs == NULL){
	return NBSCrypto_ERROR;
    }

    if ((err = hash_descriptor[hash].init(hs)) != NBSCrypto_OK) {
	goto ERR;
    }
    if ((err = hash_descriptor[hash].process(hs, key, keylen)) != NBSCrypto_OK) {
	goto ERR;
    }
    if ((err = hash_descriptor[hash].process(hs, salt, saltlen)) != NBSCrypto_OK) {
	goto ERR;
    }
    err = hash_descriptor[hash].done(hs, t);

    for(i = 1; i < c; i++)
    {
	if ((err = hash_descriptor[hash].init(hs)) != NBSCrypto_OK) {
	    goto ERR;
	}
	if ((err = hash_descriptor[hash].process(hs, t, outlen)) != NBSCrypto_OK) {
	    goto ERR;
	}
	err = hash_descriptor[hash].done(hs, t);
    }

    memcpy(out, t, outlen);

ERR:
    free(hs);

    return NBSCrypto_OK;
}

int pbkdf2(PBKDF2_TYPE type, unsigned long hash, const unsigned char *key, unsigned long keylen, const unsigned char *salt, unsigned long saltlen, int c, unsigned char *out, unsigned long outlen)
{
    int error;

    if(type == PBKDF2_TYPE_HMAC){
	error = pbkdf2Hmac(hash, key, keylen, salt, saltlen, c, out, outlen);
    }
    else if(type == PBKDF2_TYPE_AES_CMAC_PRF_128){
	error = pbkdf2AesCmacPrf128(key, keylen, salt, saltlen, c, out, outlen);
    }
    else{
	error = NBSCrypto_ERROR;
    }

    return error;
}

int pbkdf2Hmac(unsigned long hash, const unsigned char *key, unsigned long keylen, const unsigned char *salt, unsigned long saltlen, int c, unsigned char *dk, unsigned long dkLen)
{
    int i;
    int j;
    unsigned long k;
    int err;

    if ((err = is_hash_valid(hash)) != NBSCrypto_OK) {
	return err;
    }

    if(key == NULL || salt == NULL || dk == NULL){
	return NBSCrypto_ERROR;
    }

    if(c < 1){
	return NBSCrypto_ERROR;
    }


    unsigned char a[4];
    unsigned char t[hash_descriptor[hash].hashsize];
    unsigned char u[hash_descriptor[hash].hashsize];

    hmac_state *hmacContext;
    hmacContext = malloc(sizeof(hmac_state));
    if(hmacContext == NULL){
	return NBSCrypto_ERROR;
    }

    for(i = 1; dkLen > 0; i++){
	STORE32BE(i, a);

	hmac_init(hash, key, keylen, hmacContext);
	hmac_process(salt, saltlen, hmacContext);
	hmac_process(a, 4, hmacContext);
	hmac_done(u, &hash_descriptor[hash].hashsize, hmacContext);

	memcpy(t, u, hash_descriptor[hash].hashsize);

	for(j = 1; j < c; j++){
	    hmac_init(hash, key, keylen, hmacContext);
	    hmac_process(u, hash_descriptor[hash].hashsize, hmacContext);
	    hmac_done(u, &hash_descriptor[hash].hashsize, hmacContext);

	    for(k = 0; k < hash_descriptor[hash].hashsize; k++){
		t[k] ^= u[k];
	    }
	}

	k = MIN(dkLen, hash_descriptor[hash].hashsize);
	memcpy(dk, t, k);

	dk += k;
	dkLen -= k;
    }

    free(hmacContext);

    return NBSCrypto_OK;
}

int pbkdf2AesCmacPrf128(const unsigned char *p, unsigned long pLen, const unsigned char *s, unsigned long sLen, int c, unsigned char *dk, unsigned long dkLen)
{

    int i;
    int j;
    unsigned long n;
    unsigned char a[4];
    unsigned char k[16];
    unsigned char t[16];
    unsigned char u[16];
    unsigned long *outlen = NULL;

    omac_state *cmacContext;

    //Check parameters
    if(p == NULL || s == NULL || dk == NULL){
	return NBSCrypto_ERROR;
    }

    if(c < 1){
	return NBSCrypto_ERROR;
    }

    cmacContext = malloc(sizeof(omac_state));
    if(cmacContext == NULL){
	return NBSCrypto_ERROR;
    }

    const struct cipher_descriptor *cD = &aes_desc;
    register_cipher(&aes_desc);

    if(pLen == 16){
	memcpy(k, p, pLen);
    }else{
	memset(k, 0, 16);

	omac_init(0, k, 16, cmacContext);
	omac_process(p, pLen, cmacContext);
	omac_done(k, outlen, cmacContext);
    }

    for(i = 1; dkLen > 0; i++){
	STORE32BE(i, a);

	omac_init(0, k, 16, cmacContext);
	omac_process(s, sLen, cmacContext);
	omac_process(a, 4, cmacContext);
	omac_done(u, outlen, cmacContext);

	memcpy(t, u, 16);

	for(j = 1; j < c; j++){
	    omac_init(0, k, 16, cmacContext);
	    omac_process(u, 16, cmacContext);
	    omac_done(u, outlen, cmacContext);

	    for(n = 0; n < 16; n++){
		t[n] ^= u[n];
	    }
	}

	n = MIN(dkLen, 16);
	memcpy(dk, t, n);

	dk += n;
	dkLen -= n;
    }

    unregister_cipher(cD);
    free(cmacContext);

    return NBSCrypto_OK;
}
