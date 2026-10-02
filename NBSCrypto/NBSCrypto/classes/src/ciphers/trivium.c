//
//	trivium.c
//	Authors / Developers		: ???
//	Last Modified (Original)	: ???
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor trivium_desc =
{
    "trivium",
    41,
    10, 10, 0, 1152,
    NULL,
    NULL,
    NULL,
    NULL
};




#pragma mark - DEFINES
#define TRIVIUM_GET_BIT(s, n) ((s[(n - 1) / 8] >> ((n - 1) % 8)) & 1)
#define TRIVIUM_SET_BIT(s, n, v)s[(n - 1) / 8] = (s[(n - 1) / 8] & ~(1 << ((n - 1) % 8))) | (v) << ((n - 1) % 8)




#pragma mark - INLINE
static inline unsigned char _reverseInt8(unsigned char value)
{
    value = ((value & 0xF0) >> 4) | ((value & 0x0F) << 4);
    value = ((value & 0xCC) >> 2) | ((value & 0x33) << 2);
    value = ((value & 0xAA) >> 1) | ((value & 0x55) << 1);

    return value;
}

static inline unsigned char _trivium_generateBit(cipher_state *cs)
{
    int i;
    unsigned char t1;
    unsigned char t2;
    unsigned char t3;
    unsigned char z;

    t1  = TRIVIUM_GET_BIT(cs->trivium.s,  66);
    t1 ^= TRIVIUM_GET_BIT(cs->trivium.s,  93);
    t2  = TRIVIUM_GET_BIT(cs->trivium.s, 162);
    t2 ^= TRIVIUM_GET_BIT(cs->trivium.s, 177);
    t3  = TRIVIUM_GET_BIT(cs->trivium.s, 243);
    t3 ^= TRIVIUM_GET_BIT(cs->trivium.s, 288);

    z = t1 ^ t2 ^ t3;

    t1 ^= TRIVIUM_GET_BIT(cs->trivium.s,  91) & TRIVIUM_GET_BIT(cs->trivium.s,  92);
    t1 ^= TRIVIUM_GET_BIT(cs->trivium.s, 171);
    t2 ^= TRIVIUM_GET_BIT(cs->trivium.s, 175) & TRIVIUM_GET_BIT(cs->trivium.s, 176);
    t2 ^= TRIVIUM_GET_BIT(cs->trivium.s, 264);
    t3 ^= TRIVIUM_GET_BIT(cs->trivium.s, 286) & TRIVIUM_GET_BIT(cs->trivium.s, 287);
    t3 ^= TRIVIUM_GET_BIT(cs->trivium.s,  69);

    for(i = 35; i > 0; i--){
	cs->trivium.s[i] = (cs->trivium.s[i] << 1) | (cs->trivium.s[i - 1] >> 7);
    }

    cs->trivium.s[0] <<= 1;

    TRIVIUM_SET_BIT(cs->trivium.s,   1, t3);
    TRIVIUM_SET_BIT(cs->trivium.s,  94, t1);
    TRIVIUM_SET_BIT(cs->trivium.s, 178, t2);

    return z;
}

static inline unsigned char _trivium_generateByte(cipher_state *cs)
{
    int i;
    unsigned char ks;

    ks = 0;

    for(i = 0; i < 8; i++){
	ks |= _trivium_generateBit(cs) << i;
    }

    return ks;
}

static inline int _trivium_cipher(const unsigned char *in, unsigned char *out, size_t length, cipher_state *cs)
{
    size_t i;
    unsigned char ks;

    for(i = 0; i < length; i++){
	ks = _trivium_generateByte(cs);
	if(out != NULL){
	    if(in != NULL){
		out[i] = in[i] ^ ks;
	    }else{
		out[i] = ks;
	    }
	}
    }
    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS

int  trivium_setup(const unsigned char *key, int keylen, const unsigned char *iv, int ivlen, int num_rounds, cipher_state *cs)
{
    int i;

    if(cs == NULL || key == NULL || iv == NULL){
	return NBSCrypto_ERROR;
    }

    if(keylen != 10 && ivlen != 10){
	return NBSCrypto_ERROR;
    }

    memset(cs->trivium.s, 0, 36);

    for(i = 0; i < 10; i++){
	cs->trivium.s[i] = _reverseInt8(key[9 - i]);
    }

    for(i = 0; i < 10; i++){
	cs->trivium.s[12 + i] = _reverseInt8(iv[9 - i]);
    }

    for(i = 11; i < 22; i++){
	cs->trivium.s[i] = (cs->trivium.s[i + 1] << 5) | (cs->trivium.s[i] >> 3);
    }

    TRIVIUM_SET_BIT(cs->trivium.s, 286, 1);
    TRIVIUM_SET_BIT(cs->trivium.s, 287, 1);
    TRIVIUM_SET_BIT(cs->trivium.s, 288, 1);

    for(i = 0; i < (4 * 288); i++){
	_trivium_generateBit(cs);
    }

    return NBSCrypto_OK;
}

int  trivium_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cipher_state *cs)
{
    return _trivium_cipher(pt, ct, len, cs);
}

int  trivium_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cipher_state *cs)
{
    return _trivium_cipher(ct, pt, len, cs);
}

void trivium_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->trivium));
}
