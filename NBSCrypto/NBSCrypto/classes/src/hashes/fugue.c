//
//	fugue.c
//	Authors / Developers		: Shai Halevi, William E. Hall Charanjit S. Jutla
//	Last Modified (Original)	: 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor fugue_224_desc =
{
    "fugue-224",
    116,
    28,
    64,
    &fugue_224_init,
    &fugue_process,
    &fugue_done,
    NULL
};

const struct hash_descriptor fugue_256_desc =
{
    "fugue-256",
    117,
    32,
    64,
    &fugue_256_init,
    &fugue_process,
    &fugue_done,
    NULL
};

const struct hash_descriptor fugue_384_desc =
{
    "fugue-384",
    118,
    48,
    64,
    &fugue_384_init,
    &fugue_process,
    &fugue_done,
    NULL
};

const struct hash_descriptor fugue_512_desc =
{
    "fugue-512",
    119,
    64,
    64,
    &fugue_512_init,
    &fugue_process,
    &fugue_done,
    NULL
};




#pragma mark - DEFINES
#define STATE(_s,_c)     _s->fugue.State[_COLUMN(_s,_c)].d
#define BYTES(_s,_r,_c)  _s->fugue.State[_COLUMN(_s,_c)].b[_r]
#define ENTRY(_s,_r,_c)  _s[_c].b[_r]
#define ROTATE(_s,_r)    _s->fugue.Base = _COLUMN(_s,_s->fugue.Cfg->s-_r)

#define BE2HO_8(_x)  ((_x<<56)|((_x<<40)&0xff000000000000ull)|((_x<<24)&0xff0000000000ull)|((_x<<8)&0xff00000000ull)|\
((_x>>8)&0xff000000ull)|((_x>>24)&0xff0000ull)|((_x>>40)&0xff00ull)|(_x>>56))
#define HO2BE_8(_x)  BE2HO_8(_x)
#define BE2HO_4(_x)  ((_x<<24)|((_x<<8)&0xff0000)|((_x>>8)&0xff00)|(_x>>24))
#define HO2BE_4(_x)  BE2HO_4(_x)
#define LE2HO_4(_x)  (_x)
#define HO2LE_4(_x)  (_x)

#define POLY 0x11b
#define gf_0(x)   (0)
#define gf_1(x)   (x)
#define gf_2(x)   ((x<<1) ^ (((x>>7) & 1) * POLY))
#define gf_3(x)   (gf_2(x) ^ gf_1(x))
#define gf_4(x)   (gf_2(gf_2(x)))
#define gf_5(x)   (gf_4(x) ^ gf_1(x))
#define gf_6(x)   (gf_4(x) ^ gf_2(x))
#define gf_7(x)   (gf_4(x) ^ gf_2(x) ^ gf_1(x))

#define cdiv(_n,_d) ((_n + _d - 1) / _d)


static struct {
    int hashbitlen;
    fugue_hashCfg Cfg;
    unsigned int IV[16];
}hashSizes[] = {{224,{ 7,30,2,5,13},{0}},
    {256,{ 8,30,2,5,13},{0}},
    {384,{12,36,3,6,13},{0}},
    {512,{16,36,4,8,13},{0}},
    {0}
};

static union {
    unsigned long long d;
    unsigned char b[8];
}gf2mul[256];

static unsigned char init_fugue = 0;
static unsigned char aessub[256];
static fugue_hash32_s M[4];




#pragma mark - INLINE
static inline int _COLUMN(hash_state *hs, int col)
{
    int x = hs->fugue.Base+col;
    return (x<hs->fugue.Cfg->s ? x : x-hs->fugue.Cfg->s);
}

static inline void _Col_Xor(hash_state *hs, int a, int b, int c)
{
    STATE (hs, 4)        ^= STATE (hs, 0);
    if (a) STATE (hs, a) ^= STATE (hs, 0);
    if (b) STATE (hs, b) ^= STATE (hs, 0);
    if (c) STATE (hs, c) ^= STATE (hs, 0);
}

static inline void _Col_Xor_RORn(hash_state *hs, int ror, int a, int b, int c)
{
    _Col_Xor(hs, a, b, c);
    ROTATE (hs, ror);
}

static inline void _ROR3_Col_Mix(hash_state *hs)
{
    int s = hs->fugue.Cfg->s;
    int i;

    ROTATE (hs, 3);
    for (i=0; i<3; i++){
	STATE (hs, i)     ^= STATE (hs, 4+i);
	STATE (hs, s/2+i) ^= STATE (hs, 4+i);
    }
}

static inline void _input_mix(hash_state *hs, unsigned int sc)
{
    int s = hs->fugue.Cfg->s;
    int k = hs->fugue.Cfg->k;
    int i;

    STATE (hs, 6*k-2) ^= STATE (hs, 0);
    STATE (hs, 0)      = sc;
    STATE (hs, 8)     ^= sc;
    for (i=0; i<=k-2; i++)
	STATE (hs, 3*i+1) ^= STATE (hs, s-3*k+3*i);
}

static inline void _super_mix(hash_state *hs)
{
    fugue_hash32_s U[4],D,W[4];
    int r, c;

    for (r=0; r<4; r++) for (c=0; c<4; c++){
	ENTRY (U, r, c) = aessub[BYTES(hs, r, c)];
    }

    memset (&D, 0, sizeof (D));
    for (r=0; r<4; r++) for (c=0; c<4; c++){
	if (r!=c) D.b[r] ^= ENTRY (U, r, c);
    }

    for (r=0; r<4; r++) for (c=0; c<4; c++){
	ENTRY (W, r, c) = gf2mul[ENTRY(U,0,c)].b[ENTRY(M,r,0)]
	^ gf2mul[ENTRY(U,1,c)].b[ENTRY(M,r,1)]
	^ gf2mul[ENTRY(U,2,c)].b[ENTRY(M,r,2)]
	^ gf2mul[ENTRY(U,3,c)].b[ENTRY(M,r,3)]
	^ gf2mul[D.b[r]].b[ENTRY(M,c,r)];
    }

    for (r=0; r<4; r++) for (c=0; c<4; c++){
	BYTES (hs, r, (c-r)&3) = ENTRY (W, r, c);
    }
}

static inline int _fugue_next(hash_state *hs, const unsigned int *msg, unsigned long long len)
{
    int k;

    if (!hs || !hs->fugue.Cfg) return 0;
    while (len--){
	_input_mix(hs, *msg++);
	for (k=0; k<hs->fugue.Cfg->k; k++){
	    _ROR3_Col_Mix(hs);
	    _super_mix(hs);
	}
    }
    return 1;
}

static inline int _fugue_done(hash_state *hs, unsigned int *md, int *hashwordlen)
{
    if (hs && hs->fugue.Cfg){
	int n = hs->fugue.Cfg->n;
	int s = hs->fugue.Cfg->s;
	int k = hs->fugue.Cfg->k;
	int r = hs->fugue.Cfg->r;
	int t = hs->fugue.Cfg->t;
	int N = cdiv(n, 4);
	int p = s / N, j;

	for (j=0; j<r*k; j++){
	    _ROR3_Col_Mix(hs);
	    _super_mix(hs);
	}

	switch (N){
	    case 1: for (j=0; j<t; j++)
	    {
		_Col_Xor_RORn (hs, s-1, 0, 0, 0);
		_super_mix(hs);
	    }
		_Col_Xor(hs, 0, 0, 0);
		break;
	    case 2: for (j=0; j<t; j++)
	    {
		_Col_Xor_RORn (hs, p,   p,   0, 0);
		_super_mix(hs);
		_Col_Xor_RORn (hs, p-1, p+1, 0, 0);
		_super_mix(hs);
	    }
		_Col_Xor(hs, p, 0, 0);
		break;
	    case 3: for (j=0; j<t; j++)
	    {
		_Col_Xor_RORn (hs, p,   p,   2*p,   0);
		_super_mix(hs);
		_Col_Xor_RORn (hs, p,   p+1, 2*p,   0);
		_super_mix(hs);
		_Col_Xor_RORn (hs, p-1, p+1, 2*p+1, 0);
		_super_mix(hs);
	    }
		_Col_Xor(hs, p, 2*p, 0);
		break;
	    case 4: for (j=0; j<t; j++)
	    {
		_Col_Xor_RORn (hs, p,   p,   2*p,   3*p);
		_super_mix(hs);
		_Col_Xor_RORn (hs, p,   p+1, 2*p,   3*p);
		_super_mix(hs);
		_Col_Xor_RORn (hs, p,   p+1, 2*p+1, 3*p);
		_super_mix(hs);
		_Col_Xor_RORn (hs, p-1, p+1, 2*p+1, 3*p+1);
		_super_mix(hs);
	    }
		_Col_Xor(hs, p, 2*p, 3*p);
		break;
	}

	for (j=0; j<4&&j<n; j++)
	    *md++ = STATE (hs, j+1);
	for (r=1; r<=N-2; r++)
	    for (j=0; j<4; j++)
		*md++ = STATE (hs, r*p+j);
	if (n>4)
	    for (j=0; j+r*4<n; j++)
		*md++ = STATE (hs, s-p+j);
	if (hashwordlen) *hashwordlen = n;
	return 1;
    }
    return 0;
}

static inline void _fugue_iv()
{
    int i;
    hash_state hs;

    for (i=0; hashSizes[i].hashbitlen; i++){
	unsigned int Data = HO2BE_4((unsigned int)hashSizes[i].Cfg.n*32);
	memset(&hs, 0, sizeof(hash_state));
	hs.fugue.hashbitlen = hashSizes[i].Cfg.n*32;
	hs.fugue.Cfg = &hashSizes[i].Cfg;

	_fugue_next(&hs, &Data, 1);
	_fugue_done(&hs, hashSizes[i].IV, NULL);
    }
}

static inline void _init_fugue()
{
    unsigned int i,j,k,sb,X[8],SB[256];

    if (init_fugue) return;
    init_fugue = 1;

    SB[0] = 0;
    SB[1] = (1<<8)|1;
    for (i=2;i<256;i++){
	X[0] = i;
	for (j=1;j<8;j++){
	    if ((X[j]=X[j-1]<<1)&256) X[j] ^= POLY;
	}
	for (j=2;j<256;j++){
	    sb = 0;
	    for (k=0;k<8;k++){
		if (j&(1<<k)) sb ^= X[k];
	    }
	    if (sb==1) break;
	}
	SB[i] = (j<<8)|j;
    }
    for (i=0;i<256;i++){
	aessub[i] = SB[i]^0x63;
	for (j=4;j<8;j++) aessub[i] ^= (SB[i]>>j);

	gf2mul[i].b[0] = gf_0(i);
	gf2mul[i].b[1] = gf_1(i);
	gf2mul[i].b[2] = gf_2(i);
	gf2mul[i].b[3] = gf_3(i);
	gf2mul[i].b[4] = gf_4(i);
	gf2mul[i].b[5] = gf_5(i);
	gf2mul[i].b[6] = gf_6(i);
	gf2mul[i].b[7] = gf_7(i);
    }

    ENTRY (M, 0, 0) = 1; ENTRY (M, 0, 1) = 4; ENTRY (M, 0, 2) = 7; ENTRY (M, 0, 3) = 1;
    ENTRY (M, 1, 0) = 1; ENTRY (M, 1, 1) = 1; ENTRY (M, 1, 2) = 4; ENTRY (M, 1, 3) = 7;
    ENTRY (M, 2, 0) = 7; ENTRY (M, 2, 1) = 1; ENTRY (M, 2, 2) = 1; ENTRY (M, 2, 3) = 4;
    ENTRY (M, 3, 0) = 4; ENTRY (M, 3, 1) = 7; ENTRY (M, 3, 2) = 1; ENTRY (M, 3, 3) = 1;

    _fugue_iv();
}

static inline int _fugue_init(hash_state *hs, int hashbitlen)
{
    int i;

    _init_fugue();
    for (i=0; hashSizes[i].hashbitlen; i++){
	if (hashSizes[i].hashbitlen==hashbitlen){
	    int n = hashSizes[i].Cfg.n;
	    int s = hashSizes[i].Cfg.s;
	    memset(hs, 0, sizeof(hash_state));
	    hs->fugue.hashbitlen = n*32;
	    hs->fugue.Cfg = &hashSizes[i].Cfg;
	    memcpy(&hs->fugue.State[s-n].d, hashSizes[i].IV, n*4);
	    return NBSCrypto_OK;
	}
    }
    return NBSCrypto_ERROR;
}




#pragma mark - FUNCTIONS

int fugue_224_init(hash_state *hs){return _fugue_init(hs, 224);}
int fugue_256_init(hash_state *hs){return _fugue_init(hs, 256);}
int fugue_384_init(hash_state *hs){return _fugue_init(hs, 384);}
int fugue_512_init(hash_state *hs){return _fugue_init(hs, 512);}

int fugue_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    if (!hs || !hs->fugue.Cfg){
	return NBSCrypto_ERROR;
    }
    if (!inlen){
	return NBSCrypto_OK;
    }
    if (hs->fugue.TotalBits&7){
	return NBSCrypto_ERROR;
    }
    if (hs->fugue.TotalBits&31){
	int need = 32-(hs->fugue.TotalBits&31);
	if (need>inlen){
	    memcpy((unsigned char*)hs->fugue.Partial+((hs->fugue.TotalBits&31)/8), in, (inlen+7)/8);
	    hs->fugue.TotalBits += inlen;
	    return NBSCrypto_OK;
	}else{
	    memcpy((unsigned char*)hs->fugue.Partial+((hs->fugue.TotalBits&31)/8), in, need/8);
	    _fugue_next(hs, hs->fugue.Partial, 1);
	    hs->fugue.TotalBits += need;
	    inlen -= need;
	    in += need/8;
	}
    }
    if (inlen>31){
	_fugue_next(hs, (unsigned int*)in, inlen/32);
	hs->fugue.TotalBits += (inlen/32)*32;
	in += (inlen/32)*4;
	inlen &= 31;
    }
    if (inlen){
	memcpy((unsigned char*)hs->fugue.Partial, in, (inlen+7)/8);
	hs->fugue.TotalBits += inlen;
    }

    return NBSCrypto_OK;
}

int fugue_done(hash_state *hs, unsigned char *out)
{
    if (!hs || !hs->fugue.Cfg){
	return NBSCrypto_ERROR;
    }
    if (hs->fugue.TotalBits&31){
	int need = 32-(hs->fugue.TotalBits&31);
	memset((unsigned char*)hs->fugue.Partial+((hs->fugue.TotalBits&31)/8), 0, need/8);
	_fugue_next(hs, hs->fugue.Partial, 1);
    }

    hs->fugue.TotalBits = BE2HO_8(hs->fugue.TotalBits);
    _fugue_next(hs, (unsigned int*)&hs->fugue.TotalBits, 2);
    _fugue_done(hs, (unsigned int*)out, NULL);

    return NBSCrypto_OK;
}
