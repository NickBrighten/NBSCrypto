//
//	nbs_modes.h
//

#ifndef nbs_modes_h
#define nbs_modes_h


#define MAXBLOCKSIZE			144
#define NBS_ALIGN(n)
#define CTR_COUNTER_LITTLE_ENDIAN	0x0000
#define CTR_COUNTER_BIG_ENDIAN		0x1000
#define CTR_RFC3686			0x2000


#pragma mark - CIPHER MODE STRUCTS

typedef struct{
    int blocklen;
    unsigned char IV[MAXBLOCKSIZE];
    unsigned long cipher;
    cipher_state cs;
} cm_CBC;

typedef struct {
    int taglen, x;
    unsigned char PAD[16], ctr[16], CTRPAD[16], CTRlen;
    unsigned long aadlen, cipher, current_aadlen, current_ptlen, L, noncelen, ptlen;
    cipher_state cs;
} cm_CCM;

typedef struct{
    int blocklen, padlen;
    unsigned char IV[MAXBLOCKSIZE], pad[MAXBLOCKSIZE];
    unsigned long cipher;
    cipher_state cs;
} cm_CFB;

typedef struct{
    int blocklen, padlen, mode, ctrlen;
    unsigned char ctr[MAXBLOCKSIZE], pad[MAXBLOCKSIZE] NBS_ALIGN(16);
    unsigned long cipher;
    cipher_state cs;
} cm_CTR;

typedef struct {
    unsigned char N[MAXBLOCKSIZE];
    cm_CTR ctr;
    omac_state headeromac, ctomac;
} cm_EAX;

typedef struct{
    int blocklen;
    unsigned long cipher;
    cipher_state cs;
} cm_ECB;

typedef struct {
    int blocklen, padlen;
    unsigned char IV[MAXBLOCKSIZE], MIV[MAXBLOCKSIZE];
    unsigned long blockcnt, cipher;
    cipher_state cs;
} cm_F8;

typedef struct{
    int ivmode, mode, buflen;
    unsigned char H[16], X[16], Y[16], Y_0[16], buf[16];
    unsigned long cipher;
    unsigned long long totlen, pttotlen;
    cipher_state cs;
} cm_GCM;

typedef struct {
    unsigned char IV[16], tweak[16], pad[16];
    unsigned long cipher;
    cipher_state cs;
} cm_LRW;

typedef struct {
    int block_len;
    unsigned char L[MAXBLOCKSIZE], Ls[32][MAXBLOCKSIZE], Li[MAXBLOCKSIZE], Lr[MAXBLOCKSIZE], R[MAXBLOCKSIZE], checksum[MAXBLOCKSIZE];
    unsigned long block_index, cipher;
    cipher_state cs;
} cm_OCB;

typedef struct {
    int tag_len, block_len, adata_buffer_bytes;
    unsigned char Offset_0[MAXBLOCKSIZE], Offset_current[MAXBLOCKSIZE], L_dollar[MAXBLOCKSIZE], L_star[MAXBLOCKSIZE], L_[32][MAXBLOCKSIZE], tag_part[MAXBLOCKSIZE], checksum[MAXBLOCKSIZE], aSum_current[MAXBLOCKSIZE], aOffset_current[MAXBLOCKSIZE], adata_buffer[MAXBLOCKSIZE];
    unsigned long ablock_index, block_index, cipher;
    cipher_state cs;
} cm_OCB3;

typedef struct{
    int blocklen, padlen;
    unsigned char IV[MAXBLOCKSIZE];
    unsigned long cipher;
    cipher_state cs;
} cm_OFB;

typedef struct {
    unsigned long cipher;
    cipher_state cs1, cs2;
} cm_XTS;




#pragma mark - CIPHER MODE FUNCTIONS -

#pragma mark CBC
int cbc_start(unsigned long cipher, const unsigned char *iv, const unsigned char *key, int keylen, int num_rounds, cm_CBC *cbc);
int cbc_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_CBC *cbc);
int cbc_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_CBC *cbc);
int cbc_done(cm_CBC *cbc);


#pragma mark CCM
int ccm_start(unsigned long cipher, const unsigned char *key, unsigned long keylen, unsigned long ptlen, unsigned long taglen, unsigned long aadlen, cm_CCM *ccm);
int ccm_add_nonce(const unsigned char *nonce, unsigned long noncelen, cm_CCM *ccm);
int ccm_add_aad(const unsigned char *aad, unsigned long aadlen, cm_CCM *ccm);
int ccm_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, cm_CCM *ccm);
int ccm_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, cm_CCM *ccm);
int ccm_done(unsigned char *tag, unsigned long *taglen, cm_CCM *ccm);


#pragma mark CFB
int cfb_start(unsigned long cipher, const unsigned char *iv, const unsigned char *key, int keylen, int num_rounds, cm_CFB *cfb);
int cfb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_CFB *cfb);
int cfb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_CFB *cfb);
int cfb_done(cm_CFB *cfb);


#pragma mark CHACHA20POLY1305
int chacha8poly1305_encrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tag, unsigned long taglen);
int chacha8poly1305_decrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *ct, unsigned char *pt, unsigned long len, unsigned char *tag, unsigned long taglen);
int chacha12poly1305_encrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tag, unsigned long taglen);
int chacha12poly1305_decrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *ct, unsigned char *pt, unsigned long len, unsigned char *tag, unsigned long taglen);
int chacha20poly1305_encrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tag, unsigned long taglen);
int chacha20poly1305_decrypt(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *aad, unsigned long aadlen, const unsigned char *ct, unsigned char *pt, unsigned long len, unsigned char *tag, unsigned long taglen);


#pragma mark CTR
int ctr_start(unsigned long cipher, const unsigned char *iv, const unsigned char *key, int keylen, int num_rounds, int ctr_mode, cm_CTR *ctr);
int ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_CTR *ctr);
int ctr_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_CTR *ctr);
int ctr_done(cm_CTR *ctr);


#pragma mark EAX
int eax_start(unsigned long cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *header, unsigned long headerlen, cm_EAX *eax);
int eax_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_EAX *eax);
int eax_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_EAX *eax);
int eax_done(unsigned char *tag, unsigned long *taglen, cm_EAX *eax);


#pragma mark ECB
int ecb_start(unsigned long cipher, const unsigned char *key, int keylen, int num_rounds, cm_ECB *ecb);
int ecb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_ECB *ecb);
int ecb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_ECB *ecb);
int ecb_done(cm_ECB *ecb);


#pragma mark F8
int f8_start(unsigned long cipher, const unsigned char *iv, const unsigned char *key, int keylen, const unsigned char *salt_key, int skeylen, int num_rounds, cm_F8 *f8);
int f8_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_F8 *f8);
int f8_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_F8 *f8);
int f8_done(cm_F8 *f8);


#pragma mark GCM
int gcm_start(unsigned long cipher, const unsigned char *key, unsigned long keylen, int num_rounds, cm_GCM *gcm);
int gcm_add_iv(const unsigned char *iv, unsigned long ivlen, cm_GCM *gcm);
int gcm_add_aad(const unsigned char *aad, unsigned long aadlen, cm_GCM *gcm);
int gcm_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, cm_GCM *gcm);
int gcm_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, cm_GCM *gcm);
int gcm_done(unsigned char *tag, unsigned long *taglen, cm_GCM *gcm);


#pragma mark LRW
int lrw_start(unsigned long cipher, const unsigned char *iv, const unsigned char *key1, const unsigned char *key2, int keylen, int num_rounds, cm_LRW *lrw);
int lrw_add_iv(const unsigned char *iv, unsigned long ivlen, cm_LRW *lrw);
int lrw_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_LRW *lrw);
int lrw_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_LRW *lrw);
int lrw_done(cm_LRW *lrw);


#pragma mark OCB
int ocb_start(unsigned long cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce, cm_OCB *ocb);
int ocb_encrypt(const unsigned char *pt, unsigned char *ct, cm_OCB *ocb);
int ocb_decrypt(const unsigned char *ct, unsigned char *pt, cm_OCB *ocb);
int ocb_done(const unsigned char *in, unsigned char *out, unsigned long len, unsigned char *tag, unsigned long *taglen, int mode, cm_OCB *ocb);


#pragma mark OCB3
int ocb3_start(unsigned long cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, unsigned long taglen, cm_OCB3 *ocb);
int ocb3_add_aad(const unsigned char *aad, unsigned long aadlen, cm_OCB3 *ocb);
int ocb3_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_OCB3 *ocb);
int ocb3_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_OCB3 *ocb);
int ocb3_done(unsigned char *tag, unsigned long *taglen, cm_OCB3 *ocb);


#pragma mark OFB
int ofb_start(unsigned long cipher, const unsigned char *iv, const unsigned char *key, int keylen, int num_rounds, cm_OFB *ofb);
int ofb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_OFB *ofb);
int ofb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_OFB *ofb);
int ofb_done(cm_OFB *ofb);


#pragma mark XTS
int xts_start(unsigned long cipher, const unsigned char *key1, const unsigned char *key2,int keylen, int num_rounds, cm_XTS *xts);
int xts_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tweak, cm_XTS *xts);
int xts_decrypt(const unsigned char *ct, unsigned char *pt,  unsigned long len, unsigned char *tweak, cm_XTS *xts);
int xts_done(cm_XTS *xts);


#endif /* nbs_modes_h */
