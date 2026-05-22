//
//	rc6.c
//	Authors / Developers		: Ronald L. Rivest
//	Last Modified (Original)	: 1997
//


#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor rc6_desc =
{
    "rc6",
    21,
    16, 32, 16, 20,
    &rc6_setup,
    &rc6_encrypt,
    &rc6_decrypt,
    &rc6_done,
};




#pragma mark - DEFINES

#define P32 0xB7E15163
#define Q32 0x9E3779B9

#define MAX(a, b) ((a) > (b) ? (a) : (b))

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

#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define ROR32(a, n) (((a) >> (n)) | ((a) << (32 - (n))))




#pragma mark - FUNCTIONS
int rc6_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    int c, i, j, s, v;
    unsigned int a;
    unsigned int b;
    unsigned char buffer[32];

    if(cs == NULL || key == NULL){
	return NBSCrypto_ERROR;
    }

    if(keylen > 32){
	return NBSCrypto_ERROR;
    }

    memset(buffer, 0, 32);
    memcpy(buffer, key, keylen);

    for(i = 0; i < (32 / 4); i++){
	cs->rc6.l[i] = LOAD32(buffer + i * 4);
    }

    c = (keylen > 0) ? (keylen + 3) / 4 : 1;
    cs->rc6.s[0] = P32;

    for(i = 1; i < (2 * 20 + 4); i++){
	cs->rc6.s[i] = cs->rc6.s[i - 1] + Q32;
    }

    i = 0;
    j = 0;
    a = 0;
    b = 0;

    v = 3 * MAX(c, 2 * 20 + 4);

    for(s = 0; s < v; s++){
	cs->rc6.s[i] += a + b;
	cs->rc6.s[i] = ROL32(cs->rc6.s[i], 3);
	a = cs->rc6.s[i];

	cs->rc6.l[j] += a + b;
	cs->rc6.l[j] = ROL32(cs->rc6.l[j], (a + b) % 32);
	b = cs->rc6.l[j];

	if(++i >= (2 * 20 + 4)){
	    i = 0;
	}

	if(++j >= c){
	    j = 0;
	}
    }

    return NBSCrypto_OK;
}

int rc6_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    int i;
    unsigned int t;
    unsigned int u;

    unsigned int a = LOAD32(pt);
    unsigned int b = LOAD32(pt +  4);
    unsigned int c = LOAD32(pt +  8);
    unsigned int d = LOAD32(pt + 12);

    b += cs->rc6.s[0];
    d += cs->rc6.s[1];

    for(i = 1; i <= 20; i++){
	t = (b * (2 * b + 1));
	t = ROL32(t, 5);

	u = (d * (2 * d + 1));
	u = ROL32(u, 5);

	a ^= t;
	a = ROL32(a, u % 32) + cs->rc6.s[2 * i];

	c ^= u;
	c = ROL32(c, t % 32) + cs->rc6.s[2 * i + 1];

	t = a;
	a = b;
	b = c;
	c = d;
	d = t;
    }

    a += cs->rc6.s[2 * 20 + 2];
    c += cs->rc6.s[2 * 20 + 3];

    STORE32(a, ct);
    STORE32(b, ct +  4);
    STORE32(c, ct +  8);
    STORE32(d, ct + 12);

    return NBSCrypto_OK;
}

int rc6_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    int i;
    unsigned int t;
    unsigned int u;

    unsigned int a = LOAD32(ct);
    unsigned int b = LOAD32(ct + 4);
    unsigned int c = LOAD32(ct + 8);
    unsigned int d = LOAD32(ct + 12);

    c -= cs->rc6.s[2 * 20 + 3];
    a -= cs->rc6.s[2 * 20 + 2];

    for(i = 20; i > 0; i--){
	t = d;
	d = c;
	c = b;
	b = a;
	a = t;

	u = (d * (2 * d + 1));
	u = ROL32(u, 5);

	t = (b * (2 * b + 1));
	t = ROL32(t, 5);

	c -= cs->rc6.s[2 * i + 1];
	c = ROR32(c, t % 32) ^ u;

	a -= cs->rc6.s[2 * i];
	a = ROR32(a, u % 32) ^ t;
    }

    d -= cs->rc6.s[1];
    b -= cs->rc6.s[0];

    STORE32(a, pt);
    STORE32(b, pt +  4);
    STORE32(c, pt +  8);
    STORE32(d, pt + 12);

    return NBSCrypto_OK;
}

void rc6_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->rc6));
}
