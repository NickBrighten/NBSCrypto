//
//	zeromem.c
//

#include "nbs_crypto.h"


#define CIPHER_TBL_SIZE	41
#define HASH_TBL_SIZE	251




#pragma mark - Hash Functions
struct hash_descriptor hash_descriptor[HASH_TBL_SIZE] = {
    {
	NULL,	//Name of Hash
	0,	//Internal ID
	0,	//Hashsize
	0,	//Blocksize
	NULL,	//Hash INIT function
	NULL,	//Hash PROCESS function
	NULL,	//Hash DONE function
	NULL	//HMAC Block
    }
};

int is_hash_valid(unsigned long idx)
{
    if (idx < 0 || idx >= HASH_TBL_SIZE || hash_descriptor[idx].name == NULL) {
	return NBSCrypto_ERROR;
    }
    return NBSCrypto_OK;
}

int register_hash(const struct hash_descriptor *hash)
{
    int x;
    for (x = 0; x < HASH_TBL_SIZE; x++) {
	if (hash_descriptor[x].name != NULL && hash_descriptor[x].ID == hash->ID) {
	    return x;
	}
    }

    for (x = 0; x < HASH_TBL_SIZE; x++) {
	if (hash_descriptor[x].name == NULL) {
	    memcpy(&hash_descriptor[x], hash, sizeof(struct hash_descriptor));
	    return x;
	}
    }

    return -1;
}

int unregister_hash(const struct hash_descriptor *hash)
{
    int x;
    for (x = 0; x < HASH_TBL_SIZE; x++) {
	if (memcpy(&hash_descriptor[x], hash, sizeof(struct hash_descriptor)) == 0) {
	    hash_descriptor[x].name = NULL;
	    hash_descriptor[x].ID   = 0;
	    return NBSCrypto_OK;
	}
    }
    return NBSCrypto_ERROR;
}




#pragma mark - Cipher Functions
struct cipher_descriptor cipher_descriptor[CIPHER_TBL_SIZE] = {
    {
	NULL,	//Name of Cipher
	0,	//Internal ID
	0,	//Minimum KEY length
	0,	//Maximum KEY length
	0,	//Block length
	0,	//Number of rounds
	NULL,	//Cipher SETUP function
	NULL,	//Cipher EnCRYPT function
	NULL,	//Cipher DeCRYPT function
	NULL	//Cipher DONE function
    }
};

int is_cipher_valid(unsigned long idx)
{
    if (idx < 0 || idx >= CIPHER_TBL_SIZE || cipher_descriptor[idx].name == NULL) {
	return NBSCrypto_ERROR;
    }
    return NBSCrypto_OK;
}

int register_cipher(const struct cipher_descriptor *cipher)
{
    int x;
    for (x = 0; x < CIPHER_TBL_SIZE; x++) {
	if (cipher_descriptor[x].name != NULL && cipher_descriptor[x].ID == cipher->ID) {
	    return x;
	}
    }

    for (x = 0; x < CIPHER_TBL_SIZE; x++) {
	if (cipher_descriptor[x].name == NULL) {
	    memcpy(&cipher_descriptor[x], cipher, sizeof(struct cipher_descriptor));
	    return x;
	}
    }

    return -1;
}

int unregister_cipher(const struct cipher_descriptor *cipher)
{
    int x;
    for (x = 0; x < CIPHER_TBL_SIZE; x++) {
	if (memcpy(&cipher_descriptor[x], cipher, sizeof(struct cipher_descriptor)) == 0) {
	    cipher_descriptor[x].name = NULL;
	    cipher_descriptor[x].ID   = 0;
	    return NBSCrypto_OK;
	}
    }
    return NBSCrypto_ERROR;
}




#pragma mark - General Functions
int mem_neq(const void *a, const void *b, size_t len)
{
    unsigned char ret = 0;
    const unsigned char* pa;
    const unsigned char* pb;

    pa = a;
    pb = b;

    while (len-- > 0) {
	ret |= *pa ^ *pb;
	++pa;
	++pb;
    }

    ret |= ret >> 4;
    ret |= ret >> 2;
    ret |= ret >> 1;
    ret &= 1;

    return ret;
}

void zeromem(volatile void *o, size_t ol)
{
    volatile char *m = o;
    while (ol-- > 0) {
	*m++ = '\0';
    }
}

/*
 void copy_or_zeromem(const unsigned char* s, unsigned char* d, unsigned long l, int c)
 {
 unsigned long y;
 unsigned char m = 0xff;
 if (c != 0) c = 1;
 y = 0;
 m *= 1 - c;
 for (; y < l; y++) {d[y] = s[y] & m;}
 m = 0;
 }
 */
