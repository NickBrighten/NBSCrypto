//
//	serpent.c
//	Authors / Developers		: Ross Anderson, Eli Biham, Lars Knudsen
//	Last Modified (Original)	: 1998
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor serpent_desc =
{
    "serpent",
    28,
    16, 32, 16, 32,
    &serpent_setup,
    &serpent_encrypt,
    &serpent_decrypt,
    &serpent_done
};




#pragma mark - DEFINES

#define BS0(f) f(0,a,b,c,d,e)
#define AS0(f) f(1,b,e,c,a,d)
#define AS1(f) f(2,c,b,a,e,d)
#define AS2(f) f(3,a,e,b,d,c)
#define AS3(f) f(4,e,b,d,c,a)
#define AS4(f) f(5,b,a,e,c,d)
#define AS5(f) f(6,a,c,b,e,d)
#define AS6(f) f(7,a,c,d,b,e)
#define AS7(f) f(8,d,e,b,a,c)

#define BI7(f) f(8,a,b,c,d,e)
#define AI7(f) f(7,d,a,b,e,c)
#define AI6(f) f(6,a,b,c,e,d)
#define AI5(f) f(5,b,d,e,c,a)
#define AI4(f) f(4,b,c,e,a,d)
#define AI3(f) f(3,a,b,e,c,d)
#define AI2(f) f(2,b,d,e,c,a)
#define AI1(f) f(1,a,b,c,e,d)
#define AI0(f) f(0,a,d,b,e,c)

#define lt(i,a,b,c,d,e)  {		\
    a = ROLc(a, 13);			\
    c = ROLc(c, 3);			\
    d = ROLc(d ^ c ^ (a << 3), 7);	\
    b = ROLc(b ^ a ^ c, 1);		\
    a = ROLc(a ^ b ^ d, 5);		\
    c = ROLc(c ^ d ^ (b << 7), 22);	\
}

#define ilt(i,a,b,c,d,e) {		\
    c = RORc(c, 22);			\
    a = RORc(a, 5);			\
    c ^= d ^ (b << 7);			\
    a ^= b ^ d;				\
    b = RORc(b, 1);			\
    d = RORc(d, 7) ^ c ^ (a << 3);	\
    b ^= a ^ c;				\
    c = RORc(c, 3);			\
    a = RORc(a, 13);			\
}

#define S0(i, r0, r1, r2, r3, r4) {	\
    r3 ^= r0;				\
    r4 = r1;				\
    r1 &= r3;				\
    r4 ^= r2;				\
    r1 ^= r0;				\
    r0 |= r3;				\
    r0 ^= r4;				\
    r4 ^= r3;				\
    r3 ^= r2;				\
    r2 |= r1;				\
    r2 ^= r4;				\
    r4 = ~r4;				\
    r4 |= r1;				\
    r1 ^= r3;				\
    r1 ^= r4;				\
    r3 |= r0;				\
    r1 ^= r3;				\
    r4 ^= r3;				\
}

#define I0(i, r0, r1, r2, r3, r4) {	\
    r2 = ~r2;				\
    r4 = r1;				\
    r1 |= r0;				\
    r4 = ~r4;				\
    r1 ^= r2;				\
    r2 |= r4;				\
    r1 ^= r3;				\
    r0 ^= r4;				\
    r2 ^= r0;				\
    r0 &= r3;				\
    r4 ^= r0;				\
    r0 |= r1;				\
    r0 ^= r2;				\
    r3 ^= r4;				\
    r2 ^= r1;				\
    r3 ^= r0;				\
    r3 ^= r1;				\
    r2 &= r3;				\
    r4 ^= r2;				\
}

#define S1(i, r0, r1, r2, r3, r4) {	\
    r0 = ~r0;				\
    r2 = ~r2;				\
    r4 = r0;				\
    r0 &= r1;				\
    r2 ^= r0;				\
    r0 |= r3;				\
    r3 ^= r2;				\
    r1 ^= r0;				\
    r0 ^= r4;				\
    r4 |= r1;				\
    r1 ^= r3;				\
    r2 |= r0;				\
    r2 &= r4;				\
    r0 ^= r1;				\
    r1 &= r2;				\
    r1 ^= r0;				\
    r0 &= r2;				\
    r0 ^= r4;				\
}

#define I1(i, r0, r1, r2, r3, r4) {	\
    r4 = r1;				\
    r1 ^= r3;				\
    r3 &= r1;				\
    r4 ^= r2;				\
    r3 ^= r0;				\
    r0 |= r1;				\
    r2 ^= r3;				\
    r0 ^= r4;				\
    r0 |= r2;				\
    r1 ^= r3;				\
    r0 ^= r1;				\
    r1 |= r3;				\
    r1 ^= r0;				\
    r4 = ~r4;				\
    r4 ^= r1;				\
    r1 |= r0;				\
    r1 ^= r0;				\
    r1 |= r4;				\
    r3 ^= r1;				\
}

#define S2(i, r0, r1, r2, r3, r4) {	\
    r4 = r0;				\
    r0 &= r2;				\
    r0 ^= r3;				\
    r2 ^= r1;				\
    r2 ^= r0;				\
    r3 |= r4;				\
    r3 ^= r1;				\
    r4 ^= r2;				\
    r1 = r3;				\
    r3 |= r4;				\
    r3 ^= r0;				\
    r0 &= r1;				\
    r4 ^= r0;				\
    r1 ^= r3;				\
    r1 ^= r4;				\
    r4 = ~r4;				\
}

#define I2(i, r0, r1, r2, r3, r4) {	\
    r2 ^= r3;				\
    r3 ^= r0;				\
    r4 = r3;				\
    r3 &= r2;				\
    r3 ^= r1;				\
    r1 |= r2;				\
    r1 ^= r4;				\
    r4 &= r3;				\
    r2 ^= r3;				\
    r4 &= r0;				\
    r4 ^= r2;				\
    r2 &= r1;				\
    r2 |= r0;				\
    r3 = ~r3;				\
    r2 ^= r3;				\
    r0 ^= r3;				\
    r0 &= r1;				\
    r3 ^= r4;				\
    r3 ^= r0;				\
}

#define S3(i, r0, r1, r2, r3, r4) {	\
    r4 = r0;				\
    r0 |= r3;				\
    r3 ^= r1;				\
    r1 &= r4;				\
    r4 ^= r2;				\
    r2 ^= r3;				\
    r3 &= r0;				\
    r4 |= r1;				\
    r3 ^= r4;				\
    r0 ^= r1;				\
    r4 &= r0;				\
    r1 ^= r3;				\
    r4 ^= r2;				\
    r1 |= r0;				\
    r1 ^= r2;				\
    r0 ^= r3;				\
    r2 = r1;				\
    r1 |= r3;				\
    r1 ^= r0;				\
}

#define I3(i, r0, r1, r2, r3, r4) {	\
    r4 = r2;				\
    r2 ^= r1;				\
    r1 &= r2;				\
    r1 ^= r0;				\
    r0 &= r4;				\
    r4 ^= r3;				\
    r3 |= r1;				\
    r3 ^= r2;				\
    r0 ^= r4;				\
    r2 ^= r0;				\
    r0 |= r3;				\
    r0 ^= r1;				\
    r4 ^= r2;				\
    r2 &= r3;				\
    r1 |= r3;				\
    r1 ^= r2;				\
    r4 ^= r0;				\
    r2 ^= r4;				\
}

#define S4(i, r0, r1, r2, r3, r4) {	\
    r1 ^= r3;				\
    r3 = ~r3;				\
    r2 ^= r3;				\
    r3 ^= r0;				\
    r4 = r1;				\
    r1 &= r3;				\
    r1 ^= r2;				\
    r4 ^= r3;				\
    r0 ^= r4;				\
    r2 &= r4;				\
    r2 ^= r0;				\
    r0 &= r1;				\
    r3 ^= r0;				\
    r4 |= r1;				\
    r4 ^= r0;				\
    r0 |= r3;				\
    r0 ^= r2;				\
    r2 &= r3;				\
    r0 = ~r0;				\
    r4 ^= r2;				\
}

#define I4(i, r0, r1, r2, r3, r4) {	\
    r4 = r2;				\
    r2 &= r3;				\
    r2 ^= r1;				\
    r1 |= r3;				\
    r1 &= r0;				\
    r4 ^= r2;				\
    r4 ^= r1;				\
    r1 &= r2;				\
    r0 = ~r0;				\
    r3 ^= r4;				\
    r1 ^= r3;				\
    r3 &= r0;				\
    r3 ^= r2;				\
    r0 ^= r1;				\
    r2 &= r0;				\
    r3 ^= r0;				\
    r2 ^= r4;				\
    r2 |= r3;				\
    r3 ^= r0;				\
    r2 ^= r1;				\
}

#define S5(i, r0, r1, r2, r3, r4) {	\
    r0 ^= r1;				\
    r1 ^= r3;				\
    r3 = ~r3;				\
    r4 = r1;				\
    r1 &= r0;				\
    r2 ^= r3;				\
    r1 ^= r2;				\
    r2 |= r4;				\
    r4 ^= r3;				\
    r3 &= r1;				\
    r3 ^= r0;				\
    r4 ^= r1;				\
    r4 ^= r2;				\
    r2 ^= r0;				\
    r0 &= r3;				\
    r2 = ~r2;				\
    r0 ^= r4;				\
    r4 |= r3;				\
    r2 ^= r4;				\
}

#define I5(i, r0, r1, r2, r3, r4) {	\
    r1 = ~r1;				\
    r4 = r3;				\
    r2 ^= r1;				\
    r3 |= r0;				\
    r3 ^= r2;				\
    r2 |= r1;				\
    r2 &= r0;				\
    r4 ^= r3;				\
    r2 ^= r4;				\
    r4 |= r0;				\
    r4 ^= r1;				\
    r1 &= r2;				\
    r1 ^= r3;				\
    r4 ^= r2;				\
    r3 &= r4;				\
    r4 ^= r1;				\
    r3 ^= r0;				\
    r3 ^= r4;				\
    r4 = ~r4;				\
}

#define S6(i, r0, r1, r2, r3, r4) {	\
    r2 = ~r2;				\
    r4 = r3;				\
    r3 &= r0;				\
    r0 ^= r4;				\
    r3 ^= r2;				\
    r2 |= r4;				\
    r1 ^= r3;				\
    r2 ^= r0;				\
    r0 |= r1;				\
    r2 ^= r1;				\
    r4 ^= r0;				\
    r0 |= r3;				\
    r0 ^= r2;				\
    r4 ^= r3;				\
    r4 ^= r0;				\
    r3 = ~r3;				\
    r2 &= r4;				\
    r2 ^= r3;				\
}

#define I6(i, r0, r1, r2, r3, r4) {	\
    r0 ^= r2;				\
    r4 = r2;				\
    r2 &= r0;				\
    r4 ^= r3;				\
    r2 = ~r2;				\
    r3 ^= r1;				\
    r2 ^= r3;				\
    r4 |= r0;				\
    r0 ^= r2;				\
    r3 ^= r4;				\
    r4 ^= r1;				\
    r1 &= r3;				\
    r1 ^= r0;				\
    r0 ^= r3;				\
    r0 |= r2;				\
    r3 ^= r1;				\
    r4 ^= r0;				\
}

#define S7(i, r0, r1, r2, r3, r4) {	\
    r4 = r2;				\
    r2 &= r1;				\
    r2 ^= r3;				\
    r3 &= r1;				\
    r4 ^= r2;				\
    r2 ^= r1;				\
    r1 ^= r0;				\
    r0 |= r4;				\
    r0 ^= r2;				\
    r3 ^= r1;				\
    r2 ^= r3;				\
    r3 &= r0;				\
    r3 ^= r4;				\
    r4 ^= r2;				\
    r2 &= r0;				\
    r4 = ~r4;				\
    r2 ^= r4;				\
    r4 &= r0;				\
    r1 ^= r3;				\
    r4 ^= r1;				\
}

#define I7(i, r0, r1, r2, r3, r4) {	\
    r4 = r2;				\
    r2 ^= r0;				\
    r0 &= r3;				\
    r2 = ~r2;				\
    r4 |= r3;				\
    r3 ^= r1;				\
    r1 |= r0;				\
    r0 ^= r2;				\
    r2 &= r4;				\
    r1 ^= r2;				\
    r2 ^= r0;				\
    r0 |= r2;				\
    r3 &= r4;				\
    r0 ^= r3;				\
    r4 ^= r1;				\
    r3 ^= r4;				\
    r4 |= r0;				\
    r3 ^= r2;				\
    r4 ^= r2;				\
}

#define kx(r, a, b, c, d, e) {		\
    a ^= k[4 * r + 0];			\
    b ^= k[4 * r + 1];			\
    c ^= k[4 * r + 2];			\
    d ^= k[4 * r + 3];			\
}

#define lk(r, a, b, c, d, e) {		\
    a = k[(8-r)*4 + 0];			\
    b = k[(8-r)*4 + 1];			\
    c = k[(8-r)*4 + 2];			\
    d = k[(8-r)*4 + 3];			\
}

#define sk(r, a, b, c, d, e) {		\
    k[(8-r)*4 + 4] = a;			\
    k[(8-r)*4 + 5] = b;			\
    k[(8-r)*4 + 6] = c;			\
    k[(8-r)*4 + 7] = d;			\
}

#define STORE32(x, y)					\
    do {						\
	(y)[3] = (unsigned char)(((x)>>24)&255);	\
	(y)[2] = (unsigned char)(((x)>>16)&255);	\
	(y)[1] = (unsigned char)(((x)>> 8)&255);	\
	(y)[0] = (unsigned char)((x)&255);		\
    } while(0)

#define LOAD32(x, y)				\
    do {x = ((unsigned)((y)[3] & 255)<<24) |	\
	    ((unsigned)((y)[2] & 255)<<16) |	\
	    ((unsigned)((y)[1] & 255)<< 8) |	\
	    ((unsigned)((y)[0] & 255));		\
    } while(0)

#define ROLc(x, y) ((((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)
#define RORc(x, y) (((((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((y)&31)) | ((unsigned)(x)<<(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)




#pragma mark - INLINE
static inline int _setup_key(const unsigned char *key, int keylen, int rounds, unsigned *k)
{
    int i;
    unsigned t;
    unsigned k0[8] = { 0 };
    unsigned a, b, c, d, e;

    for (i = 0; i < 8 && i < keylen/4; ++i) {
	LOAD32(k0[i], key + i * 4);
    }
    if (keylen < 32) {
	k0[keylen/4] |= (unsigned)1 << ((keylen%4)*8);
    }

    t = k0[7];
    for (i = 0; i < 8; ++i) {
	k[i] = k0[i] = t = ROLc(k0[i] ^ k0[(i+3)%8] ^ k0[(i+5)%8] ^ t ^ 0x9e3779b9 ^ i, 11);
    }
    for (i = 8; i < 4*(rounds+1); ++i) {
	k[i] = t = ROLc(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i, 11);
    }
    k -= 20;

    for (i = 0; i < rounds/8; i++) {
	AS2(lk); AS2(S3); AS3(sk);
	AS1(lk); AS1(S2); AS2(sk);
	AS0(lk); AS0(S1); AS1(sk);
	BS0(lk); BS0(S0); AS0(sk);
	k += 8*4;
	AS6(lk); AS6(S7); AS7(sk);
	AS5(lk); AS5(S6); AS6(sk);
	AS4(lk); AS4(S5); AS5(sk);
	AS3(lk); AS3(S4); AS4(sk);
    }
    AS2(lk); AS2(S3); AS3(sk);

    return NBSCrypto_OK;
}

static inline int _enc_block(const unsigned char *in, unsigned char *out, const unsigned *k)
{
    unsigned a, b, c, d, e;
    unsigned int i = 1;

    LOAD32(a, in +  0);
    LOAD32(b, in +  4);
    LOAD32(c, in +  8);
    LOAD32(d, in + 12);

    do {
	BS0(kx); BS0(S0);
	AS0(lt); AS0(kx); AS0(S1);
	AS1(lt); AS1(kx); AS1(S2);
	AS2(lt); AS2(kx); AS2(S3);
	AS3(lt); AS3(kx); AS3(S4);
	AS4(lt); AS4(kx); AS4(S5);
	AS5(lt); AS5(kx); AS5(S6);
	AS6(lt); AS6(kx); AS6(S7);

	if (i == 4) break;

	++i;
	c = b;
	b = e;
	e = d;
	d = a;
	a = e;
	k += 32;
	BS0(lt);
    } while (1);

    AS7(kx);

    STORE32(d, out +  0);
    STORE32(e, out +  4);
    STORE32(b, out +  8);
    STORE32(a, out + 12);

    return NBSCrypto_OK;
}

static inline int _dec_block(const unsigned char *in, unsigned char *out, const unsigned *k)
{
    unsigned a, b, c, d, e=0;
    unsigned int i;

    LOAD32(a, in +  0);
    LOAD32(b, in +  4);
    LOAD32(c, in +  8);
    LOAD32(d, in + 12);

    i = 4;
    k += 96;

    BI7(kx);
    goto start;

    do {
	c = b;
	b = d;
	d = e;
	k -= 32;
	BI7(ilt);
    start:
	BI7(I7);
	AI7(kx); AI7(ilt); AI7(I6);
	AI6(kx); AI6(ilt); AI6(I5);
	AI5(kx); AI5(ilt); AI5(I4);
	AI4(kx); AI4(ilt); AI4(I3);
	AI3(kx); AI3(ilt); AI3(I2);
	AI2(kx); AI2(ilt); AI2(I1);
	AI1(kx); AI1(ilt); AI1(I0);
	AI0(kx);
    } while (--i != 0);

    STORE32(a, out +  0);
    STORE32(d, out +  4);
    STORE32(b, out +  8);
    STORE32(e, out + 12);

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS

int serpent_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    int err;

    if (num_rounds != 0 && num_rounds != 32) return NBSCrypto_ERROR;
    if (keylen != 16 && keylen != 24 && keylen != 32) return NBSCrypto_ERROR;

    err = _setup_key(key, keylen, 32, cs->serpent.k);
    return err;
}

int serpent_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    int err = _enc_block(pt, ct, cs->serpent.k);
    return err;
}

int serpent_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    int err = _dec_block(ct, pt, cs->serpent.k);
    return err;
}

void serpent_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->serpent));
}
