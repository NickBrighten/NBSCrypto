//
//	bcrypt.c
//	Authors / Developers		: Niels Provos, David Mazières
//	Last Modified (Original)	: 1999
//

#include "nbs_crypto.h"




#pragma mark - DEFINES

#define BCRYPT_MIN_COST		 3
#define BCRYPT_MAX_COST		31
#define BCRYPT_HASH_STRING_LEN	60

typedef enum {
    bv_A	= 0,
    bv_B	= 1,
    bv_X	= 2,
    bv_Y	= 3
}bcrypt_variants;




#pragma mark - INLINE
static inline int _blowfish_EKS_setup(int cost, const unsigned char *salt, unsigned long saltlen, const unsigned char *key, unsigned long keylen, cipher_state *cs)
{
    int error;
    unsigned i, n;

    if(cost < BCRYPT_MIN_COST || cost > BCRYPT_MAX_COST){
	return NBSCrypto_ERROR;
    }
    n = 1U << cost;

    error = blowfish_init_state(cs);
    if(!error){
	error = blowfish_expand_key(salt, saltlen, (unsigned char *) key, keylen, cs);
    }

    if(!error)
    {
	for(i = 0; i < n; i++){
	    error = blowfish_expand_key(NULL, 0, (unsigned char *) key, keylen, cs);
	    if(error){
		break;
	    }
	    error = blowfish_expand_key(NULL, 0, salt, saltlen, cs);
	    if(error){
		break;
	    }
	}
    }

    return error;
}

static inline int _bcrypt(bcrypt_variants variant, int cost, const unsigned char *salt, const unsigned char *key, char *hash, unsigned long *hashlen)
{
    int error, i;
    unsigned long n, length;
    unsigned char buffer[24];
    cipher_state *cs;

    if(salt == NULL || key == NULL || hash == NULL){
	return NBSCrypto_ERROR;
    }

    cs = malloc(sizeof(cs->blowfish));
    if(cs == NULL){
	return NBSCrypto_ERROR;
    }

    length = strlen((const char*)key) + 1;

    error = _blowfish_EKS_setup(cost, salt, 16, key, length, cs);

    if(!error){
	memcpy(buffer, "OrpheanBeholderScryDoubt", sizeof(buffer));

	for(i = 0; i < 64; i++){
	    blowfish_encrypt(buffer,	  buffer,      cs);
	    blowfish_encrypt(buffer +  8, buffer +  8, cs);
	    blowfish_encrypt(buffer + 16, buffer + 16, cs);
	}
    }

    if(!error){
	switch (variant) {
	    case bv_A:	{length = sprintf(hash, "$2a$%02u$", cost);break;}
	    case bv_B:	{length = sprintf(hash, "$2b$%02u$", cost);break;}
	    case bv_X:	{length = sprintf(hash, "$2x$%02u$", cost);break;}
	    case bv_Y:	{length = sprintf(hash, "$2y$%02u$", cost);break;}
	    default:	{length = sprintf(hash, "$2a$%02u$", cost);break;}
	}
	radix64_encode(salt, 16, (unsigned char *)(hash + length), &n);
	length += n;
	radix64_encode(buffer, 23, (unsigned char *)(hash + length), &n);
	length += n;

	if(hashlen != NULL){
	    *hashlen = length;
	}
    }

    free(cs);

    return error;
}




#pragma mark - FUNCTIONS
int bcrypt_hash_password(int variants, int cost, const unsigned char *key, char *hash, unsigned long *hashlen)
{
    int error;

    if(key == NULL || hash == NULL){
	return NBSCrypto_ERROR;
    }

    unsigned char *salt = generateSaltOrPassword(16, 0);
    error = _bcrypt(variants, cost, salt, key, hash, hashlen);

    return error;
}

int bcrypt_verify_password(const unsigned char *key, const unsigned char *hash)
{
    int cost, error, i, v;
    unsigned long n;
    unsigned char mask, salt[16];
    char *p, temp[BCRYPT_HASH_STRING_LEN + 1];

    if(key == NULL || hash == NULL){
	return NBSCrypto_ERROR;
    }

    if(strlen((const char*)hash) != BCRYPT_HASH_STRING_LEN){
	return NBSCrypto_ERROR;
    }

    char hpref[] = "   ";
    strncpy(hpref, (const char*)hash, 3);
    if(strcmp("$2a", hpref) == 0){
	v = bv_A; if(memcmp(hash, "$2a$", 4)){return NBSCrypto_ERROR;}
    }else if(strcmp("$2b", hpref) == 0){
	v = bv_B; if(memcmp(hash, "$2b$", 4)){return NBSCrypto_ERROR;}
    }else if(strcmp("$2x", hpref) == 0){
	v = bv_X; if(memcmp(hash, "$2x$", 4)){return NBSCrypto_ERROR;}
    }else if(strcmp("$2y", hpref) == 0){
	v = bv_Y; if(memcmp(hash, "$2y$", 4)){return NBSCrypto_ERROR;}
    }else{
	v = bv_A; if(memcmp(hash, "$2a$", 4)){return NBSCrypto_ERROR;}
    }

    cost = (int)strtoul((const char*)(hash + 4), &p, 10);

    if(p != (const char*)(hash + 6) || *p != '$'){
	return NBSCrypto_ERROR;
    }

    if(cost < BCRYPT_MIN_COST || cost > BCRYPT_MAX_COST){
	return NBSCrypto_ERROR;
    }

    error = radix64_decode((const unsigned char*)(hash + 7), 22, salt, &n);
    if(error){
	return error;
    }

    error = _bcrypt(v, cost, salt, key, temp, &n);
    if(error){
	return error;
    }

    for(mask = 0, i = 0; i < BCRYPT_HASH_STRING_LEN; i++){
	mask |= temp[i] ^ hash[i];
    }

    return (mask == 0) ? NBSCrypto_OK : NBSCrypto_ERROR;
}
