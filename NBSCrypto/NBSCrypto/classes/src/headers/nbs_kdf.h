//
//	nbs_kdf.h
//

#ifndef nbs_kdf_h
#define nbs_kdf_h




#pragma mark - KDF -

#pragma mark BCRYPT
int bcrypt_hash_password(const unsigned char *key, int variants, int cost, char *out, unsigned long *outlen);
int bcrypt_verify_password(const unsigned char *key, const unsigned char *hash);


#pragma mark PBKDF
typedef enum{
    PBKDF2_TYPE_HMAC			= 1,
    PBKDF2_TYPE_AES_CMAC_PRF_128	= 2
} PBKDF2_TYPE;

int pbkdf1(unsigned long hash, const unsigned char *key, unsigned long keylen, const unsigned char *salt, unsigned long saltlen, int c, unsigned char *out, unsigned long outlen);
int pbkdf2(PBKDF2_TYPE type, unsigned long hash, const unsigned char *p, size_t pLen, const unsigned char *s, size_t sLen, int c, unsigned char *dk, size_t dkLen);
int pbkdf2Hmac(unsigned long hash, const unsigned char *p, size_t pLen, const unsigned char *s, size_t sLen, int c, unsigned char *dk, size_t dkLen);
int pbkdf2AesCmacPrf128(const unsigned char *p, size_t pLen, const unsigned char *s, size_t sLen, int c, unsigned char *dk, size_t dkLen);
extern const unsigned char PBKDF2_OID[9];


#pragma mark SCRYPT
int scrypt_hash_password(const unsigned char *key, const unsigned char *salt, int n, int r, int p, unsigned char *out, size_t outlen);
int scrypt_verify_password(const unsigned char *key, const unsigned char *hash);

#endif /* nbs_kdf_h */
