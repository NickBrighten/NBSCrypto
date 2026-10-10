//
//	magma.c
//	Authors / Developers		: ???
//	Last Modified (Original)	: ???
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor magma_desc =
{
    "magma",
    18,
    32, 32, 8, 32,
    &magma_setup,
    &magma_encrypt,
    &magma_decrypt,
    &magma_done
};




#pragma mark - DEFINES
static unsigned char pi[8][16] =
{
    {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
    {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
    {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
    {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
    {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
    {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
    {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
    {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
};




#pragma mark - INLINE
static inline void magma_t_transformation(const unsigned char *in_data, unsigned char *out_data) {
    unsigned char first_part_byte, sec_part_byte;
    for (int i = 3; i >= 0; i--) {
	first_part_byte = (in_data[i] & 0x0f);
	sec_part_byte = (in_data[i] & 0xf0) >> 4;
	first_part_byte = pi[(3 - i) * 2] [first_part_byte];
	sec_part_byte = pi[(3 - i) * 2 + 1] [sec_part_byte];
	out_data[i] =  (sec_part_byte << 4) | first_part_byte;
    }
}

static inline void magma_xor(const unsigned char *a, const unsigned char *b, unsigned char *c) {
    for (int i = 0; i < 4; i++) {
	c[i] = a[i] ^ b[i];
    }
}

static inline void magma_xor_ring_32(const unsigned char *a, const unsigned char *b, unsigned char *c) {
    uint32_t internal = 0;
    for (int i = 3; i >= 0; i--) {
	internal = a[i] + b[i] + (internal >> 8);
	c[i] = internal & 0xff;
    }
}

static inline void magma_g_transformation(const unsigned char *k, const unsigned char *a, unsigned char *out_data) {
    unsigned char internal[4];
    uint32_t out_data_32;
    magma_xor_ring_32(a, k, internal);
    magma_t_transformation(internal, internal);
    out_data_32 = internal[0];
    out_data_32 = (out_data_32  << 8) + internal[1];
    out_data_32 = (out_data_32  << 8) + internal[2];
    out_data_32 = (out_data_32  << 8) + internal[3];
    out_data_32 = (out_data_32 << 11)|(out_data_32 >> 21);
    out_data[3] = out_data_32 & 0xff;
    out_data[2] = (out_data_32 >> 8) & 0xff;
    out_data[1] = (out_data_32 >> 16) & 0xff;
    out_data[0] = (out_data_32 >> 24) & 0xff;
}

static inline void magma_g_round_transformation(const unsigned char *k, const unsigned char *a, unsigned char *out_data) {
    unsigned char a_0[4];
    unsigned char a_1[4];
    unsigned char g[4];
    for(int i = 0; i < 4; i++) {
	a_1[i] = a[i];
	a_0[i] = a[4 + i];
    }
    magma_g_transformation(k, a_0, g);
    magma_xor(a_1, g, g);
    for(int i = 0; i < 4; i++) {
	a_1[i] = a_0[i];
	a_0[i] = g[i];
    }
    for(int i = 0; i < 4; i++) {
	out_data[i] = a_1[i];
	out_data[4 + i] = a_0[i];
    }
}

static inline void magma_g_final_transformation(const unsigned char *k, const unsigned char *a, unsigned char *out_data) {
    unsigned char a_0[4];
    unsigned char a_1[4];
    unsigned char g[4];
    for(int i = 0; i < 4; i++) {
	a_1[i] = a[i];
	a_0[i] = a[4 + i];
    }
    magma_g_transformation(k, a_0, g);
    magma_xor(a_1, g, g);
    for(int i = 0; i < 4; i++) {
	a_1[i] = g[i];
    }
    for(int i = 0; i < 4; i++) {
	out_data[i] = a_1[i];
	out_data[4 + i] = a_0[i];
    }
}




#pragma mark - FUNCTIONS
int magma_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    if (keylen != 16 && keylen != 24 && keylen != 32){
	return NBSCrypto_ERROR;
    }

    memcpy(cs->magma.k[ 0], key, 4);
    memcpy(cs->magma.k[ 1], key +  4, 4);
    memcpy(cs->magma.k[ 2], key +  8, 4);
    memcpy(cs->magma.k[ 3], key + 12, 4);
    memcpy(cs->magma.k[ 4], key + 16, 4);
    memcpy(cs->magma.k[ 5], key + 20, 4);
    memcpy(cs->magma.k[ 6], key + 24, 4);
    memcpy(cs->magma.k[ 7], key + 28, 4);
    memcpy(cs->magma.k[ 8], key, 4);
    memcpy(cs->magma.k[ 9], key +  4, 4);
    memcpy(cs->magma.k[10], key +  8, 4);
    memcpy(cs->magma.k[11], key + 12, 4);
    memcpy(cs->magma.k[12], key + 16, 4);
    memcpy(cs->magma.k[13], key + 20, 4);
    memcpy(cs->magma.k[14], key + 24, 4);
    memcpy(cs->magma.k[15], key + 28, 4);
    memcpy(cs->magma.k[16], key, 4);
    memcpy(cs->magma.k[17], key +  4, 4);
    memcpy(cs->magma.k[18], key +  8, 4);
    memcpy(cs->magma.k[19], key + 12, 4);
    memcpy(cs->magma.k[20], key + 16, 4);
    memcpy(cs->magma.k[21], key + 20, 4);
    memcpy(cs->magma.k[22], key + 24, 4);
    memcpy(cs->magma.k[23], key + 28, 4);
    memcpy(cs->magma.k[24], key + 28, 4);
    memcpy(cs->magma.k[25], key + 24, 4);
    memcpy(cs->magma.k[26], key + 20, 4);
    memcpy(cs->magma.k[27], key + 16, 4);
    memcpy(cs->magma.k[28], key + 12, 4);
    memcpy(cs->magma.k[29], key +  8, 4);
    memcpy(cs->magma.k[30], key +  4, 4);
    memcpy(cs->magma.k[31], key, 4);

    return NBSCrypto_OK;
}

int magma_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    magma_g_round_transformation(cs->magma.k[0], pt, ct);
    for(int i = 1; i < 31; i++) {
	magma_g_round_transformation(cs->magma.k[i], ct, ct);
    }
    magma_g_final_transformation(cs->magma.k[31], ct, ct);

    return NBSCrypto_OK;
}

int magma_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    magma_g_round_transformation(cs->magma.k[31], ct, pt);
    for(int i = 30; i > 0; i--) {
	magma_g_round_transformation(cs->magma.k[i], pt, pt);
    }
    magma_g_final_transformation(cs->magma.k[0], pt, pt);

    return NBSCrypto_OK;
}

void magma_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->magma));
}
