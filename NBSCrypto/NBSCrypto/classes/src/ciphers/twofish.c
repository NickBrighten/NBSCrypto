//
//	twofish.c
//	Authors / Developers		: Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall, Niels Ferguson
//	Last Modified (Original)	: 1998
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor twofish_desc =
{
    "twofish",
    32,
    16, 32, 16, 16,
    &twofish_setup,
    &twofish_encrypt,
    &twofish_decrypt,
    &twofish_done
};




#pragma mark - DEFINES

#define MDS_POLY	0x169
#define RS_POLY		0x14D

#define S1 cs->twofish.S[0]
#define S2 cs->twofish.S[1]
#define S3 cs->twofish.S[2]
#define S4 cs->twofish.S[3]

#define g_func(x, dum) (S1[NBS_BYTE(x,0)] ^ S2[NBS_BYTE(x,1)] ^ S3[NBS_BYTE(x,2)] ^ S4[NBS_BYTE(x,3)])
#define g1_func(x, dum)	(S2[NBS_BYTE(x,0)] ^ S3[NBS_BYTE(x,1)] ^ S4[NBS_BYTE(x,2)] ^ S1[NBS_BYTE(x,3)])

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

#define NBS_BYTE(x, n) (((x) >> (8 * (n))) & 255)


static const unsigned char RS[4][8] =
{
    { 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E },
    { 0xA4, 0x56, 0x82, 0xF3, 0X1E, 0XC6, 0X68, 0XE5 },
    { 0X02, 0XA1, 0XFC, 0XC1, 0X47, 0XAE, 0X3D, 0X19 },
    { 0XA4, 0X55, 0X87, 0X5A, 0X58, 0XDB, 0X9E, 0X03 }
};

static const unsigned char qbox[2][4][16] =
{
    {
	{ 0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4 },
	{ 0xE, 0XC, 0XB, 0X8, 0X1, 0X2, 0X3, 0X5, 0XF, 0X4, 0XA, 0X6, 0X7, 0X0, 0X9, 0XD },
	{ 0XB, 0XA, 0X5, 0XE, 0X6, 0XD, 0X9, 0X0, 0XC, 0X8, 0XF, 0X3, 0X2, 0X4, 0X7, 0X1 },
	{ 0XD, 0X7, 0XF, 0X4, 0X1, 0X2, 0X6, 0XE, 0X9, 0XB, 0X3, 0X0, 0X8, 0X5, 0XC, 0XA }
    },{
	{ 0X2, 0X8, 0XB, 0XD, 0XF, 0X7, 0X6, 0XE, 0X3, 0X1, 0X9, 0X4, 0X0, 0XA, 0XC, 0X5 },
	{ 0X1, 0XE, 0X2, 0XB, 0X4, 0XC, 0X3, 0X7, 0X6, 0XD, 0XA, 0X5, 0XF, 0X9, 0X0, 0X8 },
	{ 0X4, 0XC, 0X7, 0X5, 0X1, 0X6, 0X9, 0XA, 0X0, 0XE, 0XD, 0X8, 0X2, 0XB, 0X3, 0XF },
	{ 0xB, 0X9, 0X5, 0X1, 0XC, 0X3, 0XD, 0XE, 0X6, 0X4, 0X7, 0XF, 0X2, 0X0, 0X8, 0XA }
    }
};




#pragma mark - INLINE
static inline unsigned _sbox(int i, unsigned long x)
{
    unsigned char a0,b0,a1,b1,a2,b2,a3,b3,a4,b4,y;

    a0 = (unsigned char)((x>>4)&15);
    b0 = (unsigned char)((x)&15);
    a1 = a0 ^ b0;
    b1 = (a0 ^ ((b0<<3)|(b0>>1)) ^ (a0<<3)) & 15;
    a2 = qbox[i][0][(int)a1];
    b2 = qbox[i][1][(int)b1];
    a3 = a2 ^ b2;
    b3 = (a2 ^ ((b2<<3)|(b2>>1)) ^ (a2<<3)) & 15;
    a4 = qbox[i][2][(int)a3];
    b4 = qbox[i][3][(int)b3];

    y = (b4 << 4) + a4;

    return (unsigned)y;
}

static inline unsigned _gf_mult(unsigned a, unsigned b, unsigned p)
{
    unsigned r, B[2], P[2];

    P[1] = p;
    B[1] = b;
    r = P[0] = B[0] = 0;

    r ^= B[a&1]; a >>= 1; B[1] = P[B[1]>>7] ^ (B[1] << 1);
    r ^= B[a&1]; a >>= 1; B[1] = P[B[1]>>7] ^ (B[1] << 1);
    r ^= B[a&1]; a >>= 1; B[1] = P[B[1]>>7] ^ (B[1] << 1);
    r ^= B[a&1]; a >>= 1; B[1] = P[B[1]>>7] ^ (B[1] << 1);
    r ^= B[a&1]; a >>= 1; B[1] = P[B[1]>>7] ^ (B[1] << 1);
    r ^= B[a&1]; a >>= 1; B[1] = P[B[1]>>7] ^ (B[1] << 1);
    r ^= B[a&1]; a >>= 1; B[1] = P[B[1]>>7] ^ (B[1] << 1);
    r ^= B[a&1];

    return r;
}

static inline unsigned _mds_cmult(unsigned char in, int col)
{
    unsigned x01, x5B, xEF;

    x01 = in;
    x5B = _gf_mult(in, 0x5B, MDS_POLY);
    xEF = _gf_mult(in, 0xEF, MDS_POLY);

    switch (col) {
	case 0:
	    return (x01 << 0 ) |
	    (x5B <<  8) |
	    (xEF << 16) |
	    (xEF << 24);
	case 1:
	    return (xEF << 0 ) |
	    (xEF <<  8) |
	    (x5B << 16) |
	    (x01 << 24);
	case 2:
	    return (x5B << 0 ) |
	    (xEF <<  8) |
	    (x01 << 16) |
	    (xEF << 24);
	case 3:
	    return (x5B << 0 ) |
	    (x01 <<  8) |
	    (xEF << 16) |
	    (x5B << 24);
    }
    return 0;
}

static inline void _mds_mult(const unsigned char *in, unsigned char *out)
{
    int x;
    unsigned tmp;
    for (tmp = x = 0; x < 4; x++) {
	tmp ^= _mds_cmult(in[x], x);
    }
    STORE32(tmp, out);
}

static inline void _rs_mult(const unsigned char *in, unsigned char *out)
{
    int x, y;
    for (x = 0; x < 4; x++) {
	out[x] = 0;
	for (y = 0; y < 8; y++) {
	    out[x] ^= _gf_mult(in[y], RS[x][y], RS_POLY);
	}
    }
}

static inline void _h_func(const unsigned char *in, unsigned char *out, const unsigned char *M, int k, int offset)
{
    int x;
    unsigned char y[4];
    for (x = 0; x < 4; x++) {
	y[x] = in[x];
    }
    switch (k) {
	case 4:
	    y[0] = (unsigned char)(_sbox(1, (unsigned long)y[0]) ^ M[4 * (6 + offset) + 0]);
	    y[1] = (unsigned char)(_sbox(0, (unsigned long)y[1]) ^ M[4 * (6 + offset) + 1]);
	    y[2] = (unsigned char)(_sbox(0, (unsigned long)y[2]) ^ M[4 * (6 + offset) + 2]);
	    y[3] = (unsigned char)(_sbox(1, (unsigned long)y[3]) ^ M[4 * (6 + offset) + 3]);
	case 3:
	    y[0] = (unsigned char)(_sbox(1, (unsigned long)y[0]) ^ M[4 * (4 + offset) + 0]);
	    y[1] = (unsigned char)(_sbox(1, (unsigned long)y[1]) ^ M[4 * (4 + offset) + 1]);
	    y[2] = (unsigned char)(_sbox(0, (unsigned long)y[2]) ^ M[4 * (4 + offset) + 2]);
	    y[3] = (unsigned char)(_sbox(0, (unsigned long)y[3]) ^ M[4 * (4 + offset) + 3]);
	case 2:
	    y[0] = (unsigned char)(_sbox(1, _sbox(0, _sbox(0, (unsigned long)y[0]) ^ M[4 * (2 + offset) + 0]) ^ M[4 * (0 + offset) + 0]));
	    y[1] = (unsigned char)(_sbox(0, _sbox(0, _sbox(1, (unsigned long)y[1]) ^ M[4 * (2 + offset) + 1]) ^ M[4 * (0 + offset) + 1]));
	    y[2] = (unsigned char)(_sbox(1, _sbox(1, _sbox(0, (unsigned long)y[2]) ^ M[4 * (2 + offset) + 2]) ^ M[4 * (0 + offset) + 2]));
	    y[3] = (unsigned char)(_sbox(0, _sbox(1, _sbox(1, (unsigned long)y[3]) ^ M[4 * (2 + offset) + 3]) ^ M[4 * (0 + offset) + 3]));
    }
    _mds_mult(y, out);
}




#pragma mark - FUNCTIONS

int twofish_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    unsigned char S[4*4], tmpx0, tmpx1;
    int k, x, y;
    unsigned char tmp[4], tmp2[4], M[8*4];
    unsigned A, B;

    if (num_rounds != 16 && num_rounds != 0) {
	return NBSCrypto_ERROR;
    }

    if (keylen != 16 && keylen != 24 && keylen != 32) {
	return NBSCrypto_ERROR;
    }

    k = keylen / 8;

    for (x = 0; x < keylen; x++) {
	M[x] = key[x] & 255;
    }

    for (x = 0; x < k; x++) {
	_rs_mult(M+(x*8), S+(x*4));
    }

    for (x = 0; x < 20; x++) {
	for (y = 0; y < 4; y++) {
	    tmp[y] = x+x;
	}
	_h_func(tmp, tmp2, M, k, 0);
	LOAD32(A, tmp2);

	for (y = 0; y < 4; y++) {
	    tmp[y] = (unsigned char)(x+x+1);
	}
	_h_func(tmp, tmp2, M, k, 1);
	LOAD32(B, tmp2);
	B = ROLc(B, 8);

	cs->twofish.k[x+x] = (A + B) & 0xFFFFFFFFUL;

	cs->twofish.k[x+x+1] = ROLc(B + B + A, 9);
    }

    if (k == 2) {
	for (x = 0; x < 256; x++) {
	    tmpx0 = (unsigned char)_sbox(0, x);
	    tmpx1 = (unsigned char)_sbox(1, x);
	    cs->twofish.S[0][x] = _mds_cmult(_sbox(1, (_sbox(0, tmpx0 ^ S[0]) ^ S[4])),0);
	    cs->twofish.S[1][x] = _mds_cmult(_sbox(0, (_sbox(0, tmpx1 ^ S[1]) ^ S[5])),1);
	    cs->twofish.S[2][x] = _mds_cmult(_sbox(1, (_sbox(1, tmpx0 ^ S[2]) ^ S[6])),2);
	    cs->twofish.S[3][x] = _mds_cmult(_sbox(0, (_sbox(1, tmpx1 ^ S[3]) ^ S[7])),3);
	}
    } else if (k == 3) {
	for (x = 0; x < 256; x++) {
	    tmpx0 = (unsigned char)_sbox(0, x);
	    tmpx1 = (unsigned char)_sbox(1, x);
	    cs->twofish.S[0][x] = _mds_cmult(_sbox(1, (_sbox(0, _sbox(0, tmpx1 ^ S[0]) ^ S[4]) ^ S[8])),0);
	    cs->twofish.S[1][x] = _mds_cmult(_sbox(0, (_sbox(0, _sbox(1, tmpx1 ^ S[1]) ^ S[5]) ^ S[9])),1);
	    cs->twofish.S[2][x] = _mds_cmult(_sbox(1, (_sbox(1, _sbox(0, tmpx0 ^ S[2]) ^ S[6]) ^ S[10])),2);
	    cs->twofish.S[3][x] = _mds_cmult(_sbox(0, (_sbox(1, _sbox(1, tmpx0 ^ S[3]) ^ S[7]) ^ S[11])),3);
	}
    } else {
	for (x = 0; x < 256; x++) {
	    tmpx0 = (unsigned char)_sbox(0, x);
	    tmpx1 = (unsigned char)_sbox(1, x);
	    cs->twofish.S[0][x] = _mds_cmult(_sbox(1, (_sbox(0, _sbox(0, _sbox(1, tmpx1 ^ S[0]) ^ S[4]) ^ S[8]) ^ S[12])),0);
	    cs->twofish.S[1][x] = _mds_cmult(_sbox(0, (_sbox(0, _sbox(1, _sbox(1, tmpx0 ^ S[1]) ^ S[5]) ^ S[9]) ^ S[13])),1);
	    cs->twofish.S[2][x] = _mds_cmult(_sbox(1, (_sbox(1, _sbox(0, _sbox(0, tmpx0 ^ S[2]) ^ S[6]) ^ S[10]) ^ S[14])),2);
	    cs->twofish.S[3][x] = _mds_cmult(_sbox(0, (_sbox(1, _sbox(1, _sbox(0, tmpx1 ^ S[3]) ^ S[7]) ^ S[11]) ^ S[15])),3);
	}
    }
    return NBSCrypto_OK;
}

int twofish_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    unsigned a,b,c,d,ta,tb,tc,td,t1,t2;
    const unsigned *k;
    int r;

    LOAD32(a,&pt[ 0]);
    LOAD32(b,&pt[ 4]);
    LOAD32(c,&pt[ 8]);
    LOAD32(d,&pt[12]);

    a ^= cs->twofish.k[0];
    b ^= cs->twofish.k[1];
    c ^= cs->twofish.k[2];
    d ^= cs->twofish.k[3];

    k  = cs->twofish.k + 8;
    for (r = 8; r != 0; --r) {
	t2 = g1_func(b, cs);
	t1 = g_func(a, cs) + t2;
	c  = RORc(c ^ (t1 + k[0]), 1);
	d  = ROLc(d, 1) ^ (t2 + t1 + k[1]);

	t2 = g1_func(d, skey);
	t1 = g_func(c, skey) + t2;
	a  = RORc(a ^ (t1 + k[2]), 1);
	b  = ROLc(b, 1) ^ (t2 + t1 + k[3]);
	k += 4;
    }

    ta = c ^ cs->twofish.k[4];
    tb = d ^ cs->twofish.k[5];
    tc = a ^ cs->twofish.k[6];
    td = b ^ cs->twofish.k[7];

    STORE32(ta,&ct[ 0]);
    STORE32(tb,&ct[ 4]);
    STORE32(tc,&ct[ 8]);
    STORE32(td,&ct[12]);

    return NBSCrypto_OK;
}

int twofish_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    unsigned a,b,c,d,ta,tb,tc,td,t1,t2;
    const unsigned *k;
    int r;

    LOAD32(ta,&ct[ 0]);
    LOAD32(tb,&ct[ 4]);
    LOAD32(tc,&ct[ 8]);
    LOAD32(td,&ct[12]);

    a = tc ^ cs->twofish.k[6];
    b = td ^ cs->twofish.k[7];
    c = ta ^ cs->twofish.k[4];
    d = tb ^ cs->twofish.k[5];

    k = cs->twofish.k + 36;
    for (r = 8; r != 0; --r) {
	t2 = g1_func(d, cs);
	t1 = g_func(c, cs) + t2;
	a = ROLc(a, 1) ^ (t1 + k[2]);
	b = RORc(b ^ (t2 + t1 + k[3]), 1);

	t2 = g1_func(b, cs);
	t1 = g_func(a, cs) + t2;
	c = ROLc(c, 1) ^ (t1 + k[0]);
	d = RORc(d ^ (t2 +  t1 + k[1]), 1);
	k -= 4;
    }

    a ^= cs->twofish.k[0];
    b ^= cs->twofish.k[1];
    c ^= cs->twofish.k[2];
    d ^= cs->twofish.k[3];

    STORE32(a, &pt[ 0]);
    STORE32(b, &pt[ 4]);
    STORE32(c, &pt[ 8]);
    STORE32(d, &pt[12]);

    return NBSCrypto_OK;
}

void twofish_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->twofish));
}
