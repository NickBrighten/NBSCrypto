//
//	nbs_ciphers.h
//

#ifndef nbs_ciphers_h
#define nbs_ciphers_h


#pragma mark - CIPHER STRUCTS

struct aes_state{
    int nr;
    unsigned eK[60], dK[60];
};

struct anubis_state {
    int keyBits, R;
    unsigned eK[18 + 1][4], dK[18 + 1][4];
};

struct aria_state{
    int nr;
    unsigned k[16], eK[68], dK[68];
};

struct blowfish_state{
    unsigned P[18], S[4][256];
};

struct camellia_state{
    int R;
    unsigned long long kw[4], k[24], kl[6];
};

struct cast5_state{
    unsigned k[32], keylen;
};

struct cast128_state{
    unsigned int nr;
    unsigned km[16];
    unsigned kr[16];
};

struct cast256_state{
    unsigned km[12][4];
    unsigned char kr[12][4];
};

struct chacha_state{
    int nr, pos;
    unsigned state[16];
    unsigned char keystream[64];
};

struct des_state{
    unsigned eK[32], dK[32];
};
struct des3_state{
    unsigned eK[3][32], dK[3][32];
};

struct idea_state{
    unsigned short int eK[52], dK[52];
};

struct kasumi_state{
    unsigned KLi1[8], KLi2[8], KOi1[8], KOi2[8], KOi3[8], KIi1[8], KIi2[8], KIi3[8];
};

struct khazad_state {
    unsigned long long eK[8+1];
    unsigned long long dK[8+1];
};

struct lea_state{
    unsigned int rk[192];
    unsigned int round;
};

struct mars_state{
    unsigned int k[40];
};

struct noekeon_state{
    unsigned eK[4], dK[4];
};

struct present_state{
    unsigned long long ks[32];
};

struct rc2_state{
    unsigned xkey[64];
};

struct rc4_state{
    unsigned int x, y;
    unsigned char buf[256];
};

struct rc6_state {
    unsigned int l[32 / 4];
    unsigned int s[2 * 20 + 4];
};

typedef unsigned char safer_key_t[217];
struct safer_state{
    safer_key_t k;
};
struct saferp_state{
    long R;
    unsigned char k[33][16];
};

struct seed_state{
    unsigned eK[32], dK[32];
};

struct serpent_state{
    unsigned k[33*4];
};

struct skipjack_state{
    unsigned char k[10];
};

struct sm4_state{
    unsigned long eK[32];
    unsigned long dK[32];
    unsigned long keylen;
};

struct tea_state{
    unsigned long k[4];
};

struct twofish_state{
    unsigned S[4][256], k[40];
};

struct xtea_state{
    unsigned long A[32], B[32];
};




#pragma mark - CIPHER STATES
typedef union cipher_state{
    char dummy[1];

    struct aes_state		aes;
    struct anubis_state		anubis;
    struct aria_state		aria;
    struct blowfish_state	blowfish;
    struct camellia_state	camellia;
    struct cast128_state	cast128;
    struct cast256_state	cast256;
    struct chacha_state		chacha;
    struct des_state		des;
    struct des3_state		des3;
    struct idea_state		idea;
    struct kasumi_state		kasumi;
    struct khazad_state		khazad;
    struct lea_state		lea;
    struct mars_state		mars;
    struct noekeon_state	noekeon;
    struct present_state	present;
    struct rc2_state		rc2;
    struct rc4_state		rc4;
    struct rc6_state		rc6;
    struct safer_state		safer;
    struct saferp_state		saferp;
    struct seed_state		seed;
    struct serpent_state	serpent;
    struct skipjack_state	skipjack;
    struct sm4_state		sm4;
    struct tea_state		tea;
    struct twofish_state	twofish;
    struct xtea_state		xtea;

    void   *data;
} cipher_state;




#pragma mark - CIPHER DISCRIPTOR
extern struct cipher_descriptor {
    const char *name;
    unsigned char ID;
    int  min_key_length, max_key_length, block_length, default_rounds;

    int  (*setup)(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
    int  (*encrypt)(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
    int  (*decrypt)(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
    void (*done)(cipher_state *cs);
    int  (*keysize)(int *keysize);

    int (*accel_ecb_encrypt)(const unsigned char *pt, unsigned char *ct, unsigned long blocks, cipher_state *cs);
    int (*accel_ecb_decrypt)(const unsigned char *ct, unsigned char *pt, unsigned long blocks, cipher_state *cs);

    int (*accel_cbc_encrypt)(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, cipher_state *cs);
    int (*accel_cbc_decrypt)(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *IV, cipher_state *cs);

    int (*accel_ctr_encrypt)(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, cipher_state *cs);

    int (*accel_lrw_encrypt)(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, const unsigned char *tweak, cipher_state *cs);
    int (*accel_lrw_decrypt)(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *IV, const unsigned char *tweak, cipher_state *cs);

    int (*accel_ccm_memory)(const unsigned char *key, unsigned long keylen, cipher_state *cs, const unsigned char *nonce, unsigned long noncelen, const unsigned char *header, unsigned long headerlen, unsigned char *pt, unsigned long ptlen, unsigned char *ct, unsigned char *tag, unsigned long *taglen, int direction);

    int (*accel_gcm_memory)(const unsigned char *key, unsigned long keylen, const unsigned char *IV, unsigned long IVlen, const unsigned char *adata, unsigned long adatalen, unsigned char *pt, unsigned char *ct, unsigned long len, unsigned char *tag, unsigned long *taglen, int direction);

    int (*accel_xts_encrypt)(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *tweak, const cipher_state *cs1, const cipher_state *cs2);
    int (*accel_xts_decrypt)(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *tweak, const cipher_state *cs1, const cipher_state *cs2);

    int (*f9_memory)(const unsigned char *key, unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out, unsigned long *outlen);

    int (*omac_memory)(const unsigned char *key, unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out, unsigned long *outlen);

    int (*xcbc_memory)(const unsigned char *key, unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out, unsigned long *outlen);

} cipher_descriptor[];




#pragma mark - CIPHER FUNCTIONS -
#pragma mark AES
int  aes_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  aes_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  aes_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void aes_done(cipher_state *cs);
extern const struct cipher_descriptor aes_desc;


#pragma mark ANUBIS
int  anubis_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  anubis_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  anubis_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
int  anubis_tweak_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  anubis_tweak_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  anubis_tweak_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void anubis_done(cipher_state *cs);
extern const struct cipher_descriptor anubis_desc;
extern const struct cipher_descriptor anubis_tweak_desc;


#pragma mark ARIA
int  aria_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  aria_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  aria_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void aria_done(cipher_state *cs);
extern const struct cipher_descriptor aria_desc;


#pragma mark BLOWFISH
int  blowfish_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  blowfish_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  blowfish_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void blowfish_done(cipher_state *cs);
extern const struct cipher_descriptor blowfish_desc;


#pragma mark CAMELLIA
int  camellia_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  camellia_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  camellia_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void camellia_done(cipher_state *cs);
extern const struct cipher_descriptor camellia_desc;


#pragma mark CAST128
int  cast128_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  cast128_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  cast128_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void cast128_done(cipher_state *cs);
extern const struct cipher_descriptor cast5_desc;


#pragma mark CAST256
int  cast256_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  cast256_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  cast256_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void cast256_done(cipher_state *cs);
extern const struct cipher_descriptor cast6_desc;


#pragma mark CHACHA
int  chacha_setup(const unsigned char *key, int keylen, const unsigned char *nonce, int noncelen, int num_rounds, cipher_state *cs);
int  chacha_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cipher_state *cs);
int  chacha_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cipher_state *cs);
void chacha_done(cipher_state *cs);
extern const struct cipher_descriptor chacha_desc;


#pragma mark DES
int  des_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  des_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  des_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void des_done(cipher_state *cs);
extern const struct cipher_descriptor des_desc;

int  des3_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  des3_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  des3_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void des3_done(cipher_state *cs);
extern const struct cipher_descriptor des3_desc;


#pragma mark IDEA
int  idea_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  idea_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  idea_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void idea_done(cipher_state *cs);
extern const struct cipher_descriptor idea_desc;


#pragma mark KASUMI
int  kasumi_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  kasumi_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  kasumi_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void kasumi_done(cipher_state *cs);
extern const struct cipher_descriptor kasumi_desc;


#pragma mark KHAZAD
int  khazad_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  khazad_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  khazad_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void khazad_done(cipher_state *cs);
extern const struct cipher_descriptor khazad_desc;


#pragma mark LEA
int  lea_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  lea_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  lea_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void lea_done(cipher_state *cs);
extern const struct cipher_descriptor lea_desc;


#pragma mark MARS
int  mars_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  mars_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  mars_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void mars_done(cipher_state *cs);
extern const struct cipher_descriptor mars_desc;


#pragma mark NOEKEON
int  noekeon_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  noekeon_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  noekeon_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void noekeon_done(cipher_state *cs);
extern const struct cipher_descriptor noekeon_desc;


#pragma mark PRESENT
int  present_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  present_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  present_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void present_done(cipher_state *cs);
extern const struct cipher_descriptor present_desc;


#pragma mark RC2
int  rc2_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  rc2_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  rc2_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void rc2_done(cipher_state *cs);
extern const struct cipher_descriptor rc2_desc;


#pragma mark RC4
int  rc4_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  rc4_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cipher_state *cs);
int  rc4_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cipher_state *cs);
void rc4_done(cipher_state *cs);
extern const struct cipher_descriptor rc4_desc;


#pragma mark RC6
int  rc6_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  rc6_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  rc6_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void rc6_done(cipher_state *cs);
extern const struct cipher_descriptor rc6_desc;


#pragma mark SAFER
int  safer_k64_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  safer_k128_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  safer_sk64_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  safer_sk128_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  safer_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  safer_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void safer_done(cipher_state *cs);
int  saferp_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  saferp_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  saferp_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void saferp_done(cipher_state *cs);
extern const struct cipher_descriptor safer_k64_desc;
extern const struct cipher_descriptor safer_k128_desc;
extern const struct cipher_descriptor safer_sk64_desc;
extern const struct cipher_descriptor safer_sk128_desc;
extern const struct cipher_descriptor saferp_desc;


#pragma mark SEED
int  seed_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  seed_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  seed_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void seed_done(cipher_state *cs);
extern const struct cipher_descriptor seed_desc;


#pragma mark SERPENT
int  serpent_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  serpent_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  serpent_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void serpent_done(cipher_state *cs);
extern const struct cipher_descriptor serpent_desc;


#pragma mark SKIPJACK
int  skipjack_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  skipjack_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  skipjack_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void skipjack_done(cipher_state *cs);
extern const struct cipher_descriptor skipjack_desc;


#pragma mark SM4
int  sm4_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  sm4_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  sm4_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void sm4_done(cipher_state *cs);
extern const struct cipher_descriptor sm4_desc;


#pragma mark TEA
int  tea_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  tea_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  tea_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void tea_done(cipher_state *cs);
extern const struct cipher_descriptor tea_desc;


#pragma mark TWOFISH
int  twofish_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  twofish_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  twofish_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void twofish_done(cipher_state *cs);
extern const struct cipher_descriptor twofish_desc;


#pragma mark XTEA
int  xtea_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs);
int  xtea_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs);
int  xtea_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs);
void xtea_done(cipher_state *cs);
extern const struct cipher_descriptor xtea_desc;




#pragma mark - CIPHER GLOBAL FUNCTIONS
int is_cipher_valid(int idx);
int register_cipher(const struct cipher_descriptor *cipher);
int unregister_cipher(const struct cipher_descriptor *cipher);


#endif /* nbs_ciphers_h */
