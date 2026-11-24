//
//	nbs_kdf.h
//

#ifndef nbs_kdf_h
#define nbs_kdf_h




#pragma mark - KDF -

#pragma mark ARGON2
typedef enum Argon2_type {
    Argon2_d	= 0,
    Argon2_i	= 1,
    Argon2_id	= 2
} argon2_type;

typedef enum Argon2_version {
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} argon2_version;

int argon2_hash_password(const uint32_t t_cost, const uint32_t m_cost, const uint32_t parallelism, const void *pwd, const size_t pwdlen, const void *salt, const size_t saltlen, void *hash, const size_t hashlen, char *encoded, const size_t encodedlen, argon2_type type, const uint32_t version);
int argon2_verify_password(const unsigned char *key, const unsigned char *hash);
size_t argon2_encodedlen(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism, uint32_t saltlen, uint32_t hashlen, argon2_type type);


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
