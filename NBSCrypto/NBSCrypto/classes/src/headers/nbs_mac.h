//
//	nbs_mac.h
//

#ifndef nbs_mac_h
#define nbs_mac_h


#define MAXBLOCKSIZE			144
#define NBS_ALIGN(n)


#pragma mark - MAC STRUCTS

typedef struct {
    int cipher, block_len, buflen, keylen;
    unsigned char akey[MAXBLOCKSIZE], ACC[MAXBLOCKSIZE], IV[MAXBLOCKSIZE];
    cipher_state cs;
} f9_state;

typedef struct {
    int hash;
    unsigned char key[MAXBLOCKSIZE];
    hash_state hs;
} hmac_state;

typedef struct {
    int cipher, block_len, buflen;
    unsigned char block[MAXBLOCKSIZE], prev[MAXBLOCKSIZE], Lu[2][MAXBLOCKSIZE];
    cipher_state cs;
} omac_state;

typedef struct {
    int cipher, block_len, buflen;
    unsigned char Ls[32][MAXBLOCKSIZE], Li[MAXBLOCKSIZE], Lr[MAXBLOCKSIZE], block[MAXBLOCKSIZE], checksum[MAXBLOCKSIZE];
    unsigned long block_index;
    cipher_state cs;
} pmac_state;

typedef struct {
    int size;
    unsigned int a[5], r[4], s[4];
    unsigned char buffer[17];
} poly1305_state;




#pragma mark - MAC FUNCTIONS -

#pragma mark F9
int f9_init(int cipher, const unsigned char *key, unsigned long keylen, f9_state *f9);
int f9_process(const unsigned char *in, unsigned long inlen, f9_state *f9);
int f9_done(unsigned char *out, unsigned long *outlen, f9_state *f9);


#pragma mark HMAC
int hmac_init(int hash, const unsigned char *key, unsigned long keylen, hmac_state *hmac);
int hmac_process(const unsigned char *in, unsigned long inlen, hmac_state *hmac);
int hmac_done(unsigned char *out, unsigned long *outlen, hmac_state *hmac);


#pragma mark OMAC
int omac_init(int cipher, const unsigned char *key, unsigned long keylen, omac_state *omac);
int omac_process(const unsigned char *in, unsigned long inlen, omac_state *omac);
int omac_done(unsigned char *out, unsigned long *outlen, omac_state *omac);


#pragma mark PMAC
int pmac_init(int cipher, const unsigned char *key, unsigned long keylen, pmac_state *pmac);
int pmac_process(const unsigned char *in, unsigned long inlen, pmac_state *pmac);
int pmac_done(unsigned char *out, unsigned long *outlen, pmac_state *pmac);


#pragma mark POLY1305
int poly1305_init(const unsigned char *key, poly1305_state *poly1305);
int poly1305_process(const unsigned char *in, unsigned long inlen, poly1305_state *poly1305);
int poly1305_done(unsigned char *out, poly1305_state *poly1305);


#endif /* nbs_mac_h */
