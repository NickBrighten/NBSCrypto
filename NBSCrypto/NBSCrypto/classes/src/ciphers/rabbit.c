//
//	rabbit.c
//	Authors / Developers		: Martin Boesgaard, Mette Vesterager, Thomas Pedersen,
//					  Jesper Christiansen, Ove Scavenius
//	Last Modified (Original)	: February 2003
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor rabbit_desc =
{
    "rabbit",
    23,
    16, 16, 8, 0,
    NULL,
    NULL,
    NULL,
    NULL
};




#pragma mark - DEFINES

#define LOAD32L(x, y)				\
    do { x =((unsigned)((y)[3] & 255)<<24) |	\
	    ((unsigned)((y)[2] & 255)<<16) |	\
	    ((unsigned)((y)[1] & 255)<< 8) |	\
	    ((unsigned)((y)[0] & 255));		\
} while(0)

#define STORE32L(x, y)										\
    do {(y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);	\
	(y)[1] = (unsigned char)(((x)>> 8)&255); (y)[0] = (unsigned char)((x)&255);		\
} while(0)

#define MIN(x, y)(((x)<(y))?(x):(y))
#define ROLc(x, y)((((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFFUL)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFFUL)




#pragma mark - INLINE
static inline unsigned _rabbit_g_func(unsigned x)
{
    unsigned a, b, h, l;

    a = x &  0xFFFF;
    b = x >> 16;

    h = ((((unsigned)(a*a)>>17) + (unsigned)(a*b))>>15) + b*b;
    l = x * x;

    return (unsigned)(h^l);
}

static inline void _rabbit_next_state(rabbit_ctx *p_instance)
{
    unsigned g[8], c_old[8], i;

    for (i=0; i<8; i++) {
	c_old[i] = p_instance->c[i];
    }

    p_instance->c[0] = (unsigned)(p_instance->c[0] + 0x4D34D34D + p_instance->carry);
    p_instance->c[1] = (unsigned)(p_instance->c[1] + 0xD34D34D3 + (p_instance->c[0] < c_old[0]));
    p_instance->c[2] = (unsigned)(p_instance->c[2] + 0x34D34D34 + (p_instance->c[1] < c_old[1]));
    p_instance->c[3] = (unsigned)(p_instance->c[3] + 0x4D34D34D + (p_instance->c[2] < c_old[2]));
    p_instance->c[4] = (unsigned)(p_instance->c[4] + 0xD34D34D3 + (p_instance->c[3] < c_old[3]));
    p_instance->c[5] = (unsigned)(p_instance->c[5] + 0x34D34D34 + (p_instance->c[4] < c_old[4]));
    p_instance->c[6] = (unsigned)(p_instance->c[6] + 0x4D34D34D + (p_instance->c[5] < c_old[5]));
    p_instance->c[7] = (unsigned)(p_instance->c[7] + 0xD34D34D3 + (p_instance->c[6] < c_old[6]));
    p_instance->carry = (p_instance->c[7] < c_old[7]);

    for (i=0;i<8;i++) {
	g[i] = _rabbit_g_func((unsigned)(p_instance->x[i] + p_instance->c[i]));
    }

    p_instance->x[0] = (unsigned)(g[0] + ROLc(g[7],16) + ROLc(g[6], 16));
    p_instance->x[1] = (unsigned)(g[1] + ROLc(g[0], 8) + g[7]);
    p_instance->x[2] = (unsigned)(g[2] + ROLc(g[1],16) + ROLc(g[0], 16));
    p_instance->x[3] = (unsigned)(g[3] + ROLc(g[2], 8) + g[1]);
    p_instance->x[4] = (unsigned)(g[4] + ROLc(g[3],16) + ROLc(g[2], 16));
    p_instance->x[5] = (unsigned)(g[5] + ROLc(g[4], 8) + g[3]);
    p_instance->x[6] = (unsigned)(g[6] + ROLc(g[5],16) + ROLc(g[4], 16));
    p_instance->x[7] = (unsigned)(g[7] + ROLc(g[6], 8) + g[5]);
}

static inline void _rabbit_gen_block(cipher_state *cs, unsigned char *out)
{
    unsigned *ptr;

    _rabbit_next_state(&(cs->rabbit.work_ctx));

    ptr = (unsigned*)&(cs->rabbit.work_ctx.x);
    STORE32L((ptr[0] ^ (ptr[5]>>16) ^ (unsigned)(ptr[3]<<16)), out+ 0);
    STORE32L((ptr[2] ^ (ptr[7]>>16) ^ (unsigned)(ptr[5]<<16)), out+ 4);
    STORE32L((ptr[4] ^ (ptr[1]>>16) ^ (unsigned)(ptr[7]<<16)), out+ 8);
    STORE32L((ptr[6] ^ (ptr[3]>>16) ^ (unsigned)(ptr[1]<<16)), out+12);
}

static inline int _rabbit_crypt(const unsigned char *in, unsigned char *out, unsigned long len, cipher_state *cs)
{
    unsigned char buf[16];
    unsigned long i, j;

    if (len == 0) return NBSCrypto_OK;

    if (cs->rabbit.unused > 0) {
	j = MIN(cs->rabbit.unused, len);
	for (i = 0; i < j; ++i, cs->rabbit.unused--) out[i] = in[i] ^ cs->rabbit.block[16 - cs->rabbit.unused];
	len -= j;
	if (len == 0) return NBSCrypto_OK;
	out += j;
	in  += j;
    }
    for (;;) {
	_rabbit_gen_block(cs, buf);
	if (len <= 16) {
	    for (i = 0; i < len; ++i) out[i] = in[i] ^ buf[i];

	    cs->rabbit.unused = 16 - (int)len;
	    for (i = len; i < 16; ++i) cs->rabbit.block[i] = buf[i];

	    return NBSCrypto_OK;
	}

	for (i = 0; i < 16; ++i) out[i] = in[i] ^ buf[i];

	len -= 16;
	out += 16;
	in  += 16;
    }
}




#pragma mark - FUNCTIONS

int rabbit_setiv(const unsigned char *iv, unsigned long ivlen, cipher_state *cs)
{
    unsigned i0, i1, i2, i3, i;
    unsigned char tmpiv[8] = {0};

    if (iv && ivlen > 0) memcpy(tmpiv, iv, ivlen);

    LOAD32L(i0, tmpiv+0);
    LOAD32L(i2, tmpiv+4);
    i1 = (i0>>16) | (i2&0xFFFF0000);
    i3 = (i2<<16) | (i0&0x0000FFFF);

    cs->rabbit.work_ctx.c[0] = cs->rabbit.master_ctx.c[0] ^ i0;
    cs->rabbit.work_ctx.c[1] = cs->rabbit.master_ctx.c[1] ^ i1;
    cs->rabbit.work_ctx.c[2] = cs->rabbit.master_ctx.c[2] ^ i2;
    cs->rabbit.work_ctx.c[3] = cs->rabbit.master_ctx.c[3] ^ i3;
    cs->rabbit.work_ctx.c[4] = cs->rabbit.master_ctx.c[4] ^ i0;
    cs->rabbit.work_ctx.c[5] = cs->rabbit.master_ctx.c[5] ^ i1;
    cs->rabbit.work_ctx.c[6] = cs->rabbit.master_ctx.c[6] ^ i2;
    cs->rabbit.work_ctx.c[7] = cs->rabbit.master_ctx.c[7] ^ i3;

    for (i=0; i<8; i++) {
	cs->rabbit.work_ctx.x[i] = cs->rabbit.master_ctx.x[i];
    }
    cs->rabbit.work_ctx.carry = cs->rabbit.master_ctx.carry;

    for (i=0; i<4; i++) {
	_rabbit_next_state(&(cs->rabbit.work_ctx));
    }

    memset(&(cs->rabbit.block), 0, sizeof(cs->rabbit.block));
    cs->rabbit.unused = 0;

    return NBSCrypto_OK;
}

int rabbit_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    unsigned k0, k1, k2, k3, i;
    unsigned char  tmpkey[16] = {0};

    memset(cs, 0, sizeof(cs->rabbit));
    memcpy(tmpkey, key, keylen);

    LOAD32L(k0, tmpkey+ 0);
    LOAD32L(k1, tmpkey+ 4);
    LOAD32L(k2, tmpkey+ 8);
    LOAD32L(k3, tmpkey+12);

    cs->rabbit.master_ctx.x[0] = k0;
    cs->rabbit.master_ctx.x[2] = k1;
    cs->rabbit.master_ctx.x[4] = k2;
    cs->rabbit.master_ctx.x[6] = k3;
    cs->rabbit.master_ctx.x[1] = (unsigned)(k3<<16) | (k2>>16);
    cs->rabbit.master_ctx.x[3] = (unsigned)(k0<<16) | (k3>>16);
    cs->rabbit.master_ctx.x[5] = (unsigned)(k1<<16) | (k0>>16);
    cs->rabbit.master_ctx.x[7] = (unsigned)(k2<<16) | (k1>>16);

    cs->rabbit.master_ctx.c[0] = ROLc(k2, 16);
    cs->rabbit.master_ctx.c[2] = ROLc(k3, 16);
    cs->rabbit.master_ctx.c[4] = ROLc(k0, 16);
    cs->rabbit.master_ctx.c[6] = ROLc(k1, 16);
    cs->rabbit.master_ctx.c[1] = (k0&0xFFFF0000) | (k1&0xFFFF);
    cs->rabbit.master_ctx.c[3] = (k1&0xFFFF0000) | (k2&0xFFFF);
    cs->rabbit.master_ctx.c[5] = (k2&0xFFFF0000) | (k3&0xFFFF);
    cs->rabbit.master_ctx.c[7] = (k3&0xFFFF0000) | (k0&0xFFFF);

    cs->rabbit.master_ctx.carry = 0;

    for (i=0; i<4; i++) {
	_rabbit_next_state(&(cs->rabbit.master_ctx));
    }

    for (i=0; i<8; i++) {
	cs->rabbit.master_ctx.c[i] ^= cs->rabbit.master_ctx.x[(i+4)&0x7];
    }

    for (i=0; i<8; i++) {
	cs->rabbit.work_ctx.x[i] = cs->rabbit.master_ctx.x[i];
	cs->rabbit.work_ctx.c[i] = cs->rabbit.master_ctx.c[i];
    }
    cs->rabbit.work_ctx.carry = cs->rabbit.master_ctx.carry;

    memset(&(cs->rabbit.block), 0, sizeof(cs->rabbit.block));
    cs->rabbit.unused = 0;

    return NBSCrypto_OK;
}

int rabbit_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cipher_state *cs)
{
    return _rabbit_crypt(pt, ct, len, cs);
}

int rabbit_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cipher_state *cs)
{
    return _rabbit_crypt(ct, pt, len, cs);
}

void rabbit_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->rabbit));
}
