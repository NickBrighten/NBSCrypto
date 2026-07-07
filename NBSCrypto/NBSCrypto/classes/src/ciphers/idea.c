//
//	idea.c
//	Authors / Developers		: Xuejia Lai, James Massey
//	Last Modified (Original)	: 1992
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor idea_desc =
{
    "idea",
    12,
    16, 16, 8, 8,
    &idea_setup,
    &idea_encrypt,
    &idea_decrypt,
    &idea_done
};




#pragma mark - DEFINES

typedef unsigned short int ushort16;

#define LOW16(x)	((x)&0xffff)
#define HIGH16(x)	((x)>>16)
#define MUL(a,b) {				\
    unsigned p = (unsigned)LOW16(a) * b;	\
    if (p) {					\
	p = LOW16(p) - HIGH16(p);		\
	a = (ushort16)p - (ushort16)HIGH16(p);	\
    } else					\
	a = 1 - a - b;				\
}

#define STORE16(x,y) { (y)[0] = (unsigned char)(((x)>>8)&255); (y)[1] = (unsigned char)((x)&255); }
#define LOAD16(x,y)  { x = ((ushort16)((y)[0] & 255)<<8) | ((ushort16)((y)[1] & 255)); }




#pragma mark - INLINE
static inline ushort16 _idea_mul_inv(ushort16 x)
{
    ushort16 y = x;
    unsigned i;

    for (i = 0; i < 15; i++) {
	MUL(y, LOW16(y));
	MUL(y, x);
    }
    return LOW16(y);
}

static inline ushort16 _idea_add_inv(ushort16 x)
{
    return LOW16(0 - x);
}

static inline int _idea_setup_key(const unsigned char *key, cipher_state *cs)
{
    int i, j;
    ushort16 *e_key = cs->idea.eK;
    ushort16 *d_key = cs->idea.dK;

    for (i = 0; i < 8; i++) {
	LOAD16(e_key[i], key + 2 * i);
    }

    for (; i < 52; i++) {
	j = (i - i % 8) - 8;
	e_key[i] = LOW16((e_key[j+(i+1)%8] << 9) | (e_key[j+(i+2)%8] >> 7));
    }

    for (i = 0; i < 8; i++) {
	d_key[i*6+0] = _idea_mul_inv(e_key[(8-i)*6+0]);
	d_key[i*6+1] = _idea_add_inv(e_key[(8-i)*6+1+(i>0 ? 1 : 0)]);
	d_key[i*6+2] = _idea_add_inv(e_key[(8-i)*6+2-(i>0 ? 1 : 0)]);
	d_key[i*6+3] = _idea_mul_inv(e_key[(8-i)*6+3]);
	d_key[i*6+4] = e_key[(8-1-i)*6+4];
	d_key[i*6+5] = e_key[(8-1-i)*6+5];
    }
    d_key[i*6+0] = _idea_mul_inv(e_key[(8-i)*6+0]);
    d_key[i*6+1] = _idea_add_inv(e_key[(8-i)*6+1]);
    d_key[i*6+2] = _idea_add_inv(e_key[(8-i)*6+2]);
    d_key[i*6+3] = _idea_mul_inv(e_key[(8-i)*6+3]);

    return NBSCrypto_OK;
}

static inline int _idea_process_block(const unsigned char *in, unsigned char *out, const ushort16 *m_key)
{
    int i;
    ushort16 x0, x1, x2, x3, t0, t1;

    LOAD16(x0, in + 0);
    LOAD16(x1, in + 2);
    LOAD16(x2, in + 4);
    LOAD16(x3, in + 6);

    for (i = 0; i < 8; i++) {
	MUL(x0, m_key[i*6+0]);
	x1 += m_key[i*6+1];
	x2 += m_key[i*6+2];
	MUL(x3, m_key[i*6+3]);
	t0 = x0^x2;
	MUL(t0, m_key[i*6+4]);
	t1 = t0 + (x1^x3);
	MUL(t1, m_key[i*6+5]);
	t0 += t1;
	x0 ^= t1;
	x3 ^= t0;
	t0 ^= x1;
	x1 = x2^t1;
	x2 = t0;
    }

    MUL(x0, m_key[8*6+0]);
    x2 += m_key[8*6+1];
    x1 += m_key[8*6+2];
    MUL(x3, m_key[8*6+3]);

    STORE16(x0, out + 0);
    STORE16(x2, out + 2);
    STORE16(x1, out + 4);
    STORE16(x3, out + 6);

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS

int idea_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    if (num_rounds != 0 && num_rounds != 8) return NBSCrypto_ERROR;
    if (keylen != 16) return NBSCrypto_ERROR;

    return _idea_setup_key(key, cs);
}

int idea_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    int err = _idea_process_block(pt, ct, cs->idea.eK);
    return err;
}

int idea_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    int err = _idea_process_block(ct, pt, cs->idea.dK);
    return err;
}

void idea_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->idea));
}
