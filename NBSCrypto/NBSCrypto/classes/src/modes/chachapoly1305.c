//
//	chachapoly1305.c
//

#include "nbs_crypto.h"


#define STORE64LE(a, p)								\
    ((unsigned char *)(p))[0] = ((unsigned long long)(a) >>  0) & 0xFFU,	\
    ((unsigned char *)(p))[1] = ((unsigned long long)(a) >>  8) & 0xFFU,	\
    ((unsigned char *)(p))[2] = ((unsigned long long)(a) >> 16) & 0xFFU,	\
    ((unsigned char *)(p))[3] = ((unsigned long long)(a) >> 24) & 0xFFU,	\
    ((unsigned char *)(p))[4] = ((unsigned long long)(a) >> 32) & 0xFFU,	\
    ((unsigned char *)(p))[5] = ((unsigned long long)(a) >> 40) & 0xFFU,	\
    ((unsigned char *)(p))[6] = ((unsigned long long)(a) >> 48) & 0xFFU,	\
    ((unsigned char *)(p))[7] = ((unsigned long long)(a) >> 56) & 0xFFU




static inline int _chachaPoly1305_encrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tag, unsigned long taglen, int num_rounds)
{
    int error, padlen;
    unsigned char temp[32];
    cipher_state cs;
    poly1305_state poly1305;

    if(taglen != 16){
	return NBSCrypto_ERROR;
    }

    error = chacha_setup(key, (int)keylen, nonce, (int)noncelen, num_rounds, &cs);
    if(error)
	return error;

    chacha_encrypt(NULL, temp, 32, &cs);
    chacha_encrypt(NULL, NULL, 32, &cs);
    chacha_encrypt(pt, ct, len, &cs);

    poly1305_init(temp, &poly1305);
    poly1305_process(aad, aadlen, &poly1305);

    if((aadlen % 16) != 0)
    {
	padlen = 16 - (aadlen % 16);
	memset(temp, 0, padlen);
	poly1305_process(temp, padlen, &poly1305);
    }

    poly1305_process(ct, len, &poly1305);

    if((len % 16) != 0)
    {
	padlen = 16 - (len % 16);
	memset(temp, 0, padlen);
	poly1305_process(temp, padlen, &poly1305);
    }

    STORE64LE(aadlen, temp);
    poly1305_process(temp, 8, &poly1305);

    STORE64LE(len, temp);
    poly1305_process(temp, 8, &poly1305);

    poly1305_done(tag, &poly1305);
    chacha_done(&cs);

    return NBSCrypto_OK;
}

static inline int _chachaPoly1305_decrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *ct, unsigned char *pt, unsigned long len, unsigned char *tag, unsigned long taglen, int num_rounds)
{
    int error, padlen;
    unsigned char temp[32];
    cipher_state cs;
    poly1305_state poly1305;

    if(taglen != 16){
	return NBSCrypto_ERROR;
    }

    error = chacha_setup(key, (int)keylen, nonce, (int)noncelen, num_rounds, &cs);

    if(error){
	return error;
    }

    chacha_encrypt(NULL, temp, 32, &cs);
    chacha_encrypt(NULL, NULL, 32, &cs);

    poly1305_init(temp, &poly1305);
    poly1305_process(aad, aadlen, &poly1305);

    if((aadlen % 16) != 0)
    {
	padlen = 16 - (aadlen % 16);
	memset(temp, 0, padlen);
	poly1305_process(temp, padlen, &poly1305);
    }

    poly1305_process(ct, len, &poly1305);

    if((len % 16) != 0)
    {
	padlen = 16 - (len % 16);
	memset(temp, 0, padlen);
	poly1305_process(temp, padlen, &poly1305);
    }

    STORE64LE(aadlen, temp);
    poly1305_process(temp, 8, &poly1305);

    STORE64LE(len, temp);
    poly1305_process(temp, 8, &poly1305);

    poly1305_done(tag, &poly1305);

    chacha_decrypt(ct, pt, len, &cs);
    chacha_done(&cs);

    return NBSCrypto_OK;
}

int chacha8poly1305_encrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tag, unsigned long taglen)
{
    return _chachaPoly1305_encrypt(key, keylen, nonce, noncelen, aad, aadlen, pt, ct, len, tag, taglen, 8);
}

int chacha8poly1305_decrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *ct, unsigned char *pt, unsigned long len, unsigned char *tag, unsigned long taglen)
{
    return _chachaPoly1305_decrypt(key, keylen, nonce, noncelen, aad, aadlen, ct, pt, len, tag, taglen, 8);
}

int chacha12poly1305_encrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tag, unsigned long taglen)
{
    return _chachaPoly1305_encrypt(key, keylen, nonce, noncelen, aad, aadlen, pt, ct, len, tag, taglen, 12);
}

int chacha12poly1305_decrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *ct, unsigned char *pt, unsigned long len, unsigned char *tag, unsigned long taglen)
{
    return _chachaPoly1305_decrypt(key, keylen, nonce, noncelen, aad, aadlen, ct, pt, len, tag, taglen, 12);
}

int chacha20poly1305_encrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tag, unsigned long taglen)
{
    return _chachaPoly1305_encrypt(key, keylen, nonce, noncelen, aad, aadlen, pt, ct, len, tag, taglen, 20);
}

int chacha20poly1305_decrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *ct, unsigned char *pt, unsigned long len, unsigned char *tag, unsigned long taglen)
{
    return _chachaPoly1305_decrypt(key, keylen, nonce, noncelen, aad, aadlen, ct, pt, len, tag, taglen, 20);
}
