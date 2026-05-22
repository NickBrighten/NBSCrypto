//
//	haval.c
//	Authors / Developers		: Yuliang Zheng, Josef Pieprzyk, Jennifer Seberry
//	Last Modified (Original)	: 1992
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor haval_128_3_desc =
{
    "haval-128-3",
    129,
    16,
    128,
    &haval_128_3_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_160_3_desc =
{
    "haval-160-3",
    130,
    20,
    128,
    &haval_160_3_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_192_3_desc =
{
    "haval-192-3",
    131,
    24,
    128,
    &haval_192_3_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_224_3_desc =
{
    "haval-224-3",
    132,
    28,
    128,
    &haval_224_3_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_256_3_desc =
{
    "haval-256-3",
    133,
    32,
    128,
    &haval_256_3_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_128_4_desc =
{
    "haval-128-4",
    134,
    16,
    128,
    &haval_128_4_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_160_4_desc =
{
    "haval-160-4",
    135,
    20,
    128,
    &haval_160_4_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_192_4_desc =
{
    "haval-192-4",
    136,
    24,
    128,
    &haval_192_4_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_224_4_desc =
{
    "haval-224-4",
    137,
    28,
    128,
    &haval_224_4_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_256_4_desc =
{
    "haval-256-4",
    138,
    32,
    128,
    &haval_256_4_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_128_5_desc =
{
    "haval-128-5",
    139,
    16,
    128,
    &haval_128_5_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_160_5_desc =
{
    "haval-160-5",
    140,
    20,
    128,
    &haval_160_5_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_192_5_desc =
{
    "haval-192-5",
    141,
    24,
    128,
    &haval_192_5_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_224_5_desc =
{
    "haval-224-5",
    142,
    28,
    128,
    &haval_224_5_init,
    &haval_process,
    &haval_done,
    NULL
};

const struct hash_descriptor haval_256_5_desc =
{
    "haval-256-5",
    143,
    32,
    128,
    &haval_256_5_init,
    &haval_process,
    &haval_done,
    NULL
};




#pragma mark - DEFINES
#define HAVAL_VERSION	0x01

#define F1(x6,x5,x4,x3,x2,x1,x0)( ((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)) ^ ((x0) & (x1)) ^ (x0) )
#define F2(x6,x5,x4,x3,x2,x1,x0)( ((x1) & (x2) & (x3)) ^ ((x2) & (x4) & (x5)) ^ ((x1) & (x2)) ^ ((x1) & (x4)) ^ ((x2) & (x6)) ^ ((x3) & (x5)) ^ ((x4) & (x5)) ^ ((x0) & (x2)) ^ (x0) )
#define F3(x6,x5,x4,x3,x2,x1,x0)( ((x1) & (x2) & (x3)) ^ ((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)) ^ ((x0) & (x3)) ^ (x0) )
#define F4(x6,x5,x4,x3,x2,x1,x0)( ((x1) & (x2) & (x3)) ^ ((x2) & (x4) & (x5)) ^ ((x3) & (x4) & (x6)) ^ ((x1) & (x4)) ^ ((x2) & (x6)) ^ ((x3) & (x4)) ^ ((x3) & (x5)) ^ ((x3) & (x6)) ^ ((x4) & (x5)) ^ ((x4) & (x6)) ^ ((x0) & (x4)) ^ (x0) )
#define F5(x6,x5,x4,x3,x2,x1,x0)( ((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)) ^ ((x0) & (x1) & (x2) & (x3)) ^ ((x0) & (x5)) ^ (x0) )
#define ROTR(x,n)(((x) >> (n)) | ((x) << (32 - (n))))


static const unsigned char PADDING[128] = {
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static const unsigned D0[8] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89
};

static const unsigned K2[32] = {
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
    0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
    0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5
};

static const unsigned K3[32] = {
    0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E,
    0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60, 0xE65525F3, 0xAA55AB94,
    0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993,
    0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C
};

static const unsigned K4[32] = {
    0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991,
    0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1, 0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5,
    0x0F6D6FF3, 0x83F44239, 0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
    0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4
};

static const unsigned K5[32] = {
    0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4,
    0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
    0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B,
    0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4
};

static const short I2[32] = { 5,14,26,18,11,28, 7,16, 0,23,20,22, 1,10, 4, 8,30, 3,21, 9,17,24,29, 6,19,12,15,13, 2,25,31,27};
static const short I3[32] = {19, 9, 4,20,28,17, 8,22,29,14,25,12,24,30,16,26,31,15, 7, 3, 1, 0,18,27,13, 6,21,10,23,11, 5, 2};
static const short I4[32] = {24, 4, 0,14, 2, 7,28,23,26, 6,30,20,18,25,19, 3,22,11,31,21, 8,27,12, 9, 1,29, 5,15,17,10,16,13};
static const short I5[32] = {27, 3,21,26,17,11,20,29,19, 0,12, 7,13, 8,31,10, 5, 9,14,30,18, 6,28,24, 2,23,16,22, 4, 1,25,15};

static const short M0[32] = {0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1};
static const short M1[32] = {1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2};
static const short M2[32] = {2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3};
static const short M3[32] = {3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4};
static const short M4[32] = {4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5};
static const short M5[32] = {5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6};
static const short M6[32] = {6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7};
static const short M7[32] = {7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0};




#pragma mark - INLINE
static inline void _haval_encode(unsigned char *out, unsigned *in, unsigned int inlen)
{
    for (int i=0,j=0;j<inlen;i++,j+=4) {
	out[j]	= (unsigned char) (in[i] & 0xff);
	out[j+1]= (unsigned char) ((in[i] >> 8) & 0xff);
	out[j+2]= (unsigned char) ((in[i] >> 16) & 0xff);
	out[j+3]= (unsigned char) ((in[i] >> 24) & 0xff);
    }
}

static inline void _haval_decode(unsigned *out, const unsigned char *in, unsigned int inlen)
{
    for (int i=0,j=0;j<inlen;i++,j+=4){
	out[i] = ((unsigned)in[j]) | (((unsigned)in[j+1]) << 8) | (((unsigned) in[j+2]) << 16) | (((unsigned) in[j+3]) << 24);
    }
}

static inline void _haval_compress(unsigned state[8], const unsigned char block[128], char passes)
{
    unsigned E[8];
    unsigned x[32];

    _haval_decode(x, block, 128);

    for(int i=0;i<8;i++){E[i]=state[i];}

    switch (passes){
	case 3:{
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F1(E[M1[i]],E[M0[i]],E[M3[i]],E[M5[i]],E[M6[i]],E[M2[i]],E[M4[i]]),7)+ROTR(E[M7[i]],11)+x[i];
	    }
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F2(E[M4[i]],E[M2[i]],E[M1[i]],E[M0[i]],E[M5[i]],E[M3[i]],E[M6[i]]),7)+ROTR(E[M7[i]],11)+x[I2[i]]+K2[i];
	    }
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F3(E[M6[i]],E[M1[i]],E[M2[i]],E[M3[i]],E[M4[i]],E[M5[i]],E[M0[i]]),7)+ROTR(E[M7[i]],11)+x[I3[i]]+K3[i];
	    }
	    break;
	}
	case 4:{
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F1(E[M2[i]],E[M6[i]],E[M1[i]],E[M4[i]],E[M5[i]],E[M3[i]],E[M0[i]]),7)+ROTR(E[M7[i]],11)+x[i];
	    }
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F2(E[M3[i]],E[M5[i]],E[M2[i]],E[M0[i]],E[M1[i]],E[M6[i]],E[M4[i]]),7)+ROTR(E[M7[i]],11)+x[I2[i]]+K2[i];
	    }
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F3(E[M1[i]],E[M4[i]],E[M3[i]],E[M6[i]],E[M0[i]],E[M2[i]],E[M5[i]]),7)+ROTR(E[M7[i]],11)+x[I3[i]]+K3[i];
	    }
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F4(E[M6[i]],E[M4[i]],E[M0[i]],E[M5[i]],E[M2[i]],E[M1[i]],E[M3[i]]),7)+ROTR(E[M7[i]],11)+x[I4[i]]+K4[i];
	    }
	    break;
	}
	case 5:{
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F1(E[M3[i]],E[M4[i]],E[M1[i]],E[M0[i]],E[M5[i]],E[M2[i]],E[M6[i]]),7)+ROTR(E[M7[i]],11)+x[i];
	    }
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F2(E[M6[i]],E[M2[i]],E[M1[i]],E[M0[i]],E[M3[i]],E[M4[i]],E[M5[i]]),7)+ROTR(E[M7[i]],11)+x[I2[i]]+K2[i];
	    }
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F3(E[M2[i]],E[M6[i]],E[M0[i]],E[M4[i]],E[M3[i]],E[M1[i]],E[M5[i]]),7)+ROTR(E[M7[i]],11)+x[I3[i]]+K3[i];
	    }
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F4(E[M1[i]],E[M5[i]],E[M3[i]],E[M2[i]],E[M0[i]],E[M4[i]],E[M6[i]]),7)+ROTR(E[M7[i]],11)+x[I4[i]]+K4[i];
	    }
	    for(int i=0;i<32;i++){
		E[7-(i%8)]=ROTR(F5(E[M2[i]],E[M5[i]],E[M0[i]],E[M6[i]],E[M4[i]],E[M3[i]],E[M1[i]]),7)+ROTR(E[M7[i]],11)+x[I5[i]]+K5[i];
	    }
	    break;
	}
    }

    for(int i=0;i<8;i++){state[i]+=E[i];}

    zeromem((unsigned char*) x, sizeof(x));
}

static inline int _haval_init(hash_state *hs, char p, short b)
{
    hs->haval.count[0] = hs->haval.count[1] = 0;
    for (int i=0;i<8;i++){
	hs->haval.state[i] = D0[i];
	hs->haval.passes = p;
	hs->haval.output = b;
	hs->haval.transform = _haval_compress;
    }

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int haval_128_3_init(hash_state *hs){return _haval_init(hs, 3, 128);}
int haval_160_3_init(hash_state *hs){return _haval_init(hs, 3, 160);}
int haval_192_3_init(hash_state *hs){return _haval_init(hs, 3, 192);}
int haval_224_3_init(hash_state *hs){return _haval_init(hs, 3, 224);}
int haval_256_3_init(hash_state *hs){return _haval_init(hs, 3, 256);}
int haval_128_4_init(hash_state *hs){return _haval_init(hs, 4, 128);}
int haval_160_4_init(hash_state *hs){return _haval_init(hs, 4, 160);}
int haval_192_4_init(hash_state *hs){return _haval_init(hs, 4, 192);}
int haval_224_4_init(hash_state *hs){return _haval_init(hs, 4, 224);}
int haval_256_4_init(hash_state *hs){return _haval_init(hs, 4, 256);}
int haval_128_5_init(hash_state *hs){return _haval_init(hs, 5, 128);}
int haval_160_5_init(hash_state *hs){return _haval_init(hs, 5, 160);}
int haval_192_5_init(hash_state *hs){return _haval_init(hs, 5, 192);}
int haval_224_5_init(hash_state *hs){return _haval_init(hs, 5, 224);}
int haval_256_5_init(hash_state *hs){return _haval_init(hs, 5, 256);}

int haval_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned int i, idx, plen;

    idx = (unsigned int) ((hs->haval.count[0] >> 3) & 0x7F);

    if ((hs->haval.count[0] += ((unsigned) inlen << 3)) < ((unsigned) inlen << 3)) {
	hs->haval.count[1]++;
    }
    hs->haval.count[1] += ((unsigned) inlen >> 29);

    plen = 128 - idx;

    if (inlen >= plen) {
	memcpy((unsigned char*) & hs->haval.buffer[idx], (unsigned char*) in, plen);
	hs->haval.transform(hs->haval.state, hs->haval.buffer, hs->haval.passes);

	for (i = plen; i + 127 < inlen; i += 128) {
	    hs->haval.transform(hs->haval.state, &in[i], hs->haval.passes);
	}

	idx = 0;
    } else {
	i = 0;
    }

    memcpy((unsigned char*) &hs->haval.buffer[idx], (unsigned char*) &in[i], inlen - i);

    return NBSCrypto_OK;
}

int haval_done(hash_state *hs, unsigned char *out)
{
    unsigned char bits[10];
    unsigned int index, padLen;

    bits[0] = (HAVAL_VERSION & 0x07) | ((hs->haval.passes & 0x07) << 3) | ((hs->haval.output & 0x03) << 6);
    bits[1] = (hs->haval.output >> 2);

    _haval_encode(bits + 2, hs->haval.count, 8);

    index = (unsigned int) ((hs->haval.count[0] >> 3) & 0x7f);
    padLen = (index < 118) ? (118 - index) : (246 - index);

    haval_process(hs, PADDING, padLen);
    haval_process(hs, bits, 10);

    switch (hs->haval.output) {
	case 128:{
	    hs->haval.state[3] += (hs->haval.state[7] & 0xFF000000) | (hs->haval.state[6] & 0x00FF0000) | (hs->haval.state[5] & 0x0000FF00) | (hs->haval.state[4] & 0x000000FF);
	    hs->haval.state[2] += (((hs->haval.state[7] & 0x00FF0000) | (hs->haval.state[6] & 0x0000FF00) | (hs->haval.state[5] & 0x000000FF)) << 8) | ((hs->haval.state[4] & 0xFF000000) >> 24);
	    hs->haval.state[1] += (((hs->haval.state[7] & 0x0000FF00) | (hs->haval.state[6] & 0x000000FF)) << 16) | (((hs->haval.state[5] & 0xFF000000) | (hs->haval.state[4] & 0x00FF0000)) >> 16);
	    hs->haval.state[0] +=  ((hs->haval.state[7] & 0x000000FF) << 24) | (((hs->haval.state[6] & 0xFF000000) | (hs->haval.state[5] & 0x00FF0000) | (hs->haval.state[4] & 0x0000FF00)) >> 8);

	    _haval_encode(out, hs->haval.state, 16);
	    break;
	}
	case 160:{
	    hs->haval.state[4] += ((hs->haval.state[7] & 0xFE000000) | (hs->haval.state[6] & 0x01F80000) | (hs->haval.state[5] & 0x0007F000)) >> 12;
	    hs->haval.state[3] += ((hs->haval.state[7] & 0x01F80000) | (hs->haval.state[6] & 0x0007F000) | (hs->haval.state[5] & 0x00000FC0)) >> 6;
	    hs->haval.state[2] +=  (hs->haval.state[7] & 0x0007F000) | (hs->haval.state[6] & 0x00000FC0) | (hs->haval.state[5] & 0x0000003F);
	    hs->haval.state[1] += ROTR((hs->haval.state[7] & 0x00000FC0) | (hs->haval.state[6] & 0x0000003F) | (hs->haval.state[5] & 0xFE000000), 25);
	    hs->haval.state[0] += ROTR((hs->haval.state[7] & 0x0000003F) | (hs->haval.state[6] & 0xFE000000) | (hs->haval.state[5] & 0x01F80000), 19);

	    _haval_encode(out, hs->haval.state, 20);
	    break;
	}
	case 192:{
	    hs->haval.state[5] += ((hs->haval.state[7] & 0xFC000000) | (hs->haval.state[6] & 0x03E00000)) >> 21;
	    hs->haval.state[4] += ((hs->haval.state[7] & 0x03E00000) | (hs->haval.state[6] & 0x001F0000)) >> 16;
	    hs->haval.state[3] += ((hs->haval.state[7] & 0x001F0000) | (hs->haval.state[6] & 0x0000FC00)) >> 10;
	    hs->haval.state[2] += ((hs->haval.state[7] & 0x0000FC00) | (hs->haval.state[6] & 0x000003E0)) >>  5;
	    hs->haval.state[1] +=  (hs->haval.state[7] & 0x000003E0) | (hs->haval.state[6] & 0x0000001F);
	    hs->haval.state[0] += ROTR((hs->haval.state[7] & 0x0000001F) | (hs->haval.state[6] & 0xFC000000), 26);

	    _haval_encode(out, hs->haval.state, 24);
	    break;
	}
	case 224:{
	    hs->haval.state[6] +=  hs->haval.state[7]        & 0x0000000F;
	    hs->haval.state[5] += (hs->haval.state[7] >>  4) & 0x0000001F;
	    hs->haval.state[4] += (hs->haval.state[7] >>  9) & 0x0000000F;
	    hs->haval.state[3] += (hs->haval.state[7] >> 13) & 0x0000001F;
	    hs->haval.state[2] += (hs->haval.state[7] >> 18) & 0x0000000F;
	    hs->haval.state[1] += (hs->haval.state[7] >> 22) & 0x0000001F;
	    hs->haval.state[0] += (hs->haval.state[7] >> 27) & 0x0000001F;

	    _haval_encode(out, hs->haval.state, 28);
	    break;
	}
	case 256:{
	    _haval_encode(out, hs->haval.state, 32);
	    break;
	}
    }

    return NBSCrypto_OK;
}
