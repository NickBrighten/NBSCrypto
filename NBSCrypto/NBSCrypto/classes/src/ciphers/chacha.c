//
//	chacha.c
//	Authors / Developers		: Daniel J. Bernstein
//	Last Modified (Original)	: 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor chacha_desc =
{
    "chacha",
    9,
    16, 32, 16, 20,
    NULL,
    NULL,
    NULL,
    NULL
};




#pragma mark - DEFINES

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define QR(a, b, c, d) {	\
    a += b;			\
    d ^= a;			\
    d = ROL32(d, 16);		\
    c += d;			\
    b ^= c;			\
    b = ROL32(b, 12);		\
    a += b;			\
    d ^= a;			\
    d = ROL32(d, 8);		\
    c += d;			\
    b ^= c;			\
    b = ROL32(b, 7);		\
}

#define LOAD32(p) (					\
    ((unsigned int)(((unsigned char *)(p))[0]) <<  0) |	\
    ((unsigned int)(((unsigned char *)(p))[1]) <<  8) |	\
    ((unsigned int)(((unsigned char *)(p))[2]) << 16) |	\
    ((unsigned int)(((unsigned char *)(p))[3]) << 24))

#define STORE32(a, p)							\
    ((unsigned char *)(p))[0] = ((unsigned int)(a) >>  0) & 0xFFU,	\
    ((unsigned char *)(p))[1] = ((unsigned int)(a) >>  8) & 0xFFU,	\
    ((unsigned char *)(p))[2] = ((unsigned int)(a) >> 16) & 0xFFU,	\
    ((unsigned char *)(p))[3] = ((unsigned int)(a) >> 24) & 0xFFU




#pragma mark - INLINE
static inline void _chacha_processBlock(cipher_state *cs)
{
    int i;
    unsigned int w[16];

    for(i = 0; i < 16; i++){
	w[i] = cs->chacha.state[i];
    }

    for(i = 0; i < cs->chacha.nr; i += 2){
	QR(w[0], w[4], w[ 8], w[12]);
	QR(w[1], w[5], w[ 9], w[13]);
	QR(w[2], w[6], w[10], w[14]);
	QR(w[3], w[7], w[11], w[15]);
	QR(w[0], w[5], w[10], w[15]);
	QR(w[1], w[6], w[11], w[12]);
	QR(w[2], w[7], w[ 8], w[13]);
	QR(w[3], w[4], w[ 9], w[14]);
    }

    for(i = 0; i < 16; i++){
	w[i] += cs->chacha.state[i];
    }

    for(i = 0; i < 16; i++){
	STORE32(w[i], cs->chacha.keystream + i * 4);
    }
}

static inline int _chacha_crypt(const unsigned char *in, unsigned char *out, int len, cipher_state *cs)
{
    int i;
    int n;
    unsigned char *k;

    while(len > 0){
	if(cs->chacha.pos == 0 || cs->chacha.pos >= 64){
	    _chacha_processBlock(cs);
	    cs->chacha.state[12]++;

	    if(cs->chacha.state[12] == 0){
		cs->chacha.state[13]++;
	    }

	    cs->chacha.pos = 0;
	}

	n = MIN(len, 64 - cs->chacha.pos);

	if(out != NULL){
	    k = cs->chacha.keystream + cs->chacha.pos;

	    if(in != NULL){
		for(i = 0; i < n; i++){
		    out[i] = in[i] ^ k[i];
		}

		in += n;
	    }else{
		for(i = 0; i < n; i++){
		    out[i] = k[i];
		}
	    }

	    out += n;
	}

	cs->chacha.pos += n;

	len -= n;
    }

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS

int chacha_setup(const unsigned char *key, int keylen, const unsigned char *nonce, int noncelen, int num_rounds, cipher_state *cs)
{
    unsigned int *w;

    if(cs == NULL || key == NULL || nonce == NULL){
	return NBSCrypto_ERROR;
    }

    if(num_rounds != 8 && num_rounds != 12 && num_rounds != 20){
	return NBSCrypto_ERROR;
    }

    cs->chacha.nr = num_rounds;
    w = cs->chacha.state;

    if(keylen == 16){
	w[ 0] = 0x61707865;
	w[ 1] = 0x3120646E;
	w[ 2] = 0x79622D36;
	w[ 3] = 0x6B206574;
	w[ 4] = LOAD32(key);
	w[ 5] = LOAD32(key +  4);
	w[ 6] = LOAD32(key +  8);
	w[ 7] = LOAD32(key + 12);
	w[ 8] = LOAD32(key);
	w[ 9] = LOAD32(key +  4);
	w[10] = LOAD32(key +  8);
	w[11] = LOAD32(key + 12);
    }else if(keylen == 32){
	w[ 0] = 0x61707865;
	w[ 1] = 0x3320646E;
	w[ 2] = 0x79622D32;
	w[ 3] = 0x6B206574;
	w[ 4] = LOAD32(key);
	w[ 5] = LOAD32(key +  4);
	w[ 6] = LOAD32(key +  8);
	w[ 7] = LOAD32(key + 12);
	w[ 8] = LOAD32(key + 16);
	w[ 9] = LOAD32(key + 20);
	w[10] = LOAD32(key + 24);
	w[11] = LOAD32(key + 28);
    }else{
	return NBSCrypto_ERROR;
    }

    if(noncelen == 8){
	w[12] = 0;
	w[13] = 0;
	w[14] = LOAD32(nonce);
	w[15] = LOAD32(nonce +  4);
    }else if(noncelen == 12){
	w[12] = 0;
	w[13] = LOAD32(nonce);
	w[14] = LOAD32(nonce +  4);
	w[15] = LOAD32(nonce +  8);
    }else if(noncelen == 16){
	w[12] = LOAD32(nonce);
	w[13] = LOAD32(nonce +  4);
	w[14] = LOAD32(nonce +  8);
	w[15] = LOAD32(nonce + 12);
    }else{
	return NBSCrypto_ERROR;
    }

    cs->chacha.pos = 0;

    return NBSCrypto_OK;
}

int chacha_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cipher_state *cs)
{
    return _chacha_crypt(pt, ct, (int)len, cs);
}

int chacha_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cipher_state *cs)
{
    return _chacha_crypt(ct, pt, (int)len, cs);
}

void chacha_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->chacha));
}
