//
//	arirang.c
//	Authors / Developers		: Jian Guo, Krystian Matusiewicz, Lars R. Knudsen, San Ling, Huaxiong Wang
//	Last Modified (Original)	: 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor arirang_224_desc =
{
    "arirang-224",
    2,
    28,
    64,
    &arirang_224_init,
    &arirang_process,
    &arirang_done,
    NULL
};

const struct hash_descriptor arirang_256_desc =
{
    "arirang-256",
    3,
    32,
    64,
    &arirang_256_init,
    &arirang_process,
    &arirang_done,
    NULL
};

const struct hash_descriptor arirang_384_desc =
{
    "arirang-384",
    4,
    48,
    64,
    &arirang_384_init,
    &arirang_process,
    &arirang_done,
    NULL
};

const struct hash_descriptor arirang_512_desc =
{
    "arirang-512",
    5,
    64,
    64,
    &arirang_512_init,
    &arirang_process,
    &arirang_done,
    NULL
};




#pragma mark - DEFINES

#define byte(x, n) ((unsigned char)((x) >> (8 * n)))
#define ff_mult(a, b) (a && b ? pow_tab[(log_tab[a] + log_tab[b]) % 255] : 0)
#define ROTL_DWORD(x, n) ((unsigned int)((x) << (n)) | (unsigned int)((x) >> (32-(n))))
#define ROTL_QWORD(x, n) ((unsigned long long)((x) << (n)) | (unsigned long long)((x) >> (64-(n))))

#define ENDIAN_REVERSE_DWORD(dwS) ((ROTL_DWORD((dwS),  8) & 0x00ff00ff) | (ROTL_DWORD((dwS), 24) & 0xff00ff00))
#define ENDIAN_REVERSE_QWORD(w, x) {								\
unsigned long long tmp = (w);								\
tmp = (tmp >> 32) | (tmp << 32);							\
tmp = ((tmp & 0xff00ff00ff00ff00ULL) >>  8) | ((tmp & 0x00ff00ff00ff00ffULL) <<  8);	\
(x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | ((tmp & 0x0000ffff0000ffffULL) << 16);	\
}

#define BIG_B2D(B, D)		D = ENDIAN_REVERSE_DWORD(*(unsigned int *)(B))
#define BIG_Q2B(D, B)		ENDIAN_REVERSE_QWORD(D, *(unsigned long long *)(B))
#define BIG_D2B(D, B)		*(unsigned int *)(B) = ENDIAN_REVERSE_DWORD(D)
#define LITTLE_B2D(B, D)	D = *(unsigned int *)(B)
#define LITTLE_D2B(D, B)	*(unsigned int *)(B) = (unsigned int)(D)

#define GetData(x) ENDIAN_REVERSE_DWORD(x)

unsigned char sbx[256];
unsigned char F2[256];
unsigned char F3[256];
unsigned char F4[256];
unsigned char F8[256];
unsigned char F9[256];
unsigned char FA[256];

static const unsigned int K256[16] = {
    0x517cc1b7, 0x76517cc1, 0xbd76517c, 0x2dbd7651,
    0x272dbd76, 0xcb272dbd, 0x90cb272d, 0x0a90cb27,
    0xec0a90cb, 0x5bec0a90, 0x9a5bec0a, 0xe69a5bec,
    0xb7e69a5b, 0xc1b7e69a, 0x7cc1b7e6, 0x517cc1b7
};

static const unsigned long long K512[16] = {
    0x517cc1b727220a94, 0x2db6517cc1b72722, 0xe6952db6517cc1b7, 0x90cbe6952db6517c,
    0x7cca90cbe6952db6, 0xcb237cca90cbe695, 0x765ecb237cca90cb, 0xec01765ecb237cca,
    0xb7e9ec01765ecb23, 0xbd7db7e9ec01765e, 0x9a5fbd7db7e9ec01, 0x5be89a5fbd7db7e9,
    0x0a945be89a5fbd7d, 0x27220a945be89a5f, 0xc1b727220a945be8, 0x517cc1b727220a94
};




#pragma mark - INLINE

static inline void _gen_tabs(void)
{
    int i;
    unsigned char p, q;
    unsigned char log_tab[256];
    unsigned char pow_tab[256];

    for(i = 0,p = 1;i<256;i++){
	pow_tab[i] = (unsigned char)p;
	log_tab[p] = (unsigned char)i;
	p = p ^ (p << 1) ^ (p & 0x80 ? 0x01b : 0);
    }

    for(i=0;i<256;i++){
	p = (i ? pow_tab[255 - log_tab[i]] : 0); q = p;
	q = (q >> 7) | (q << 1); p ^= q;
	q = (q >> 7) | (q << 1); p ^= q;
	q = (q >> 7) | (q << 1); p ^= q;
	q = (q >> 7) | (q << 1); p ^= q ^ 0x63;
	sbx[i] = p;
    }

    for(i=0;i<256;i++){
	F2[i] = ff_mult(i,2);
	F3[i] = ff_mult(i,3);
	F4[i] = ff_mult(i,4);
	F8[i] = ff_mult(i,8);
	F9[i] = ff_mult(i,9);
	FA[i] = ff_mult(i,10);
    }
}

static inline void _step256(unsigned int R[8], unsigned int M1, unsigned int M2)
{
    unsigned int temp1,temp2;

    R[0] ^= M1;
    R[4] ^= M2;

    temp1 =  (unsigned int)(sbx[byte(R[0], 0)])		^
    ((unsigned int)(sbx[byte(R[0], 1)]) <<  8)	^
    ((unsigned int)(sbx[byte(R[0], 2)]) << 16)	^
    ((unsigned int)(sbx[byte(R[0], 3)]) << 24);
    temp2 =  (unsigned int)(sbx[byte(R[4], 0)])		^
    ((unsigned int)(sbx[byte(R[4], 1)]) <<  8)	^
    ((unsigned int)(sbx[byte(R[4], 2)]) << 16)	^
    ((unsigned int)(sbx[byte(R[4], 3)]) << 24);
    temp1 = ( (unsigned int)(F2[byte(temp1,0)])		^
	     (unsigned int)(F3[byte(temp1,1)])		^
	     (unsigned int)(   byte(temp1,2) )		^
	     (unsigned int)(   byte(temp1,3) ))	^
    (((unsigned int)(   byte(temp1,0) )		^
      (unsigned int)(F2[byte(temp1,1)])		^
      (unsigned int)(F3[byte(temp1,2)])		^
      (unsigned int)(   byte(temp1,3) )) <<  8)	^
    (((unsigned int)(   byte(temp1,0) )		^
      (unsigned int)(   byte(temp1,1) )		^
      (unsigned int)(F2[byte(temp1,2)])		^
      (unsigned int)(F3[byte(temp1,3)])) << 16)	^
    (((unsigned int)(F3[byte(temp1,0)])		^
      (unsigned int)(   byte(temp1,1) )		^
      (unsigned int)(   byte(temp1,2) )		^
      (unsigned int)(F2[byte(temp1,3)])) << 24);
    temp2 = ( (unsigned int)(F2[byte(temp2,0)])		^
	     (unsigned int)(F3[byte(temp2,1)])		^
	     (unsigned int)(   byte(temp2,2) )		^
	     (unsigned int)(   byte(temp2,3) ))	^
    (((unsigned int)(   byte(temp2,0) )		^
      (unsigned int)(F2[byte(temp2,1)])		^
      (unsigned int)(F3[byte(temp2,2)])		^
      (unsigned int)(   byte(temp2,3) )) <<  8)	^
    (((unsigned int)(   byte(temp2,0) )		^
      (unsigned int)(   byte(temp2,1) )		^
      (unsigned int)(F2[byte(temp2,2)])		^
      (unsigned int)(F3[byte(temp2,3)])) << 16)	^
    (((unsigned int)(F3[byte(temp2,0)])		^
      (unsigned int)(   byte(temp2,1) )		^
      (unsigned int)(   byte(temp2,2) )		^
      (unsigned int)(F2[byte(temp2,3)])) << 24);

    R[1] ^= temp1;
    R[2] ^= ROTL_DWORD(temp1, 13);
    R[3] ^= ROTL_DWORD(temp1, 23);
    R[5] ^= temp2;
    R[6] ^= ROTL_DWORD(temp2, 29);
    R[7] ^= ROTL_DWORD(temp2, 7);

    temp1=R[7];
    R[7]=R[6];
    R[6]=R[5];
    R[5]=R[4];
    R[4]=R[3];
    R[3]=R[2];
    R[2]=R[1];
    R[1]=R[0];
    R[0]=temp1;
}

static inline void _step512(unsigned long long R[8], unsigned long long M1, unsigned long long M2)
{
    unsigned long long temp1,temp2;

    R[0] ^= M1;
    R[4] ^= M2;

    temp1 =  (unsigned long long)(sbx[byte(R[0], 0)])		^
    ((unsigned long long)(sbx[byte(R[0], 1)]) <<  8)	^
    ((unsigned long long)(sbx[byte(R[0], 2)]) << 16)	^
    ((unsigned long long)(sbx[byte(R[0], 3)]) << 24)	^
    ((unsigned long long)(sbx[byte(R[0], 4)]) << 32)	^
    ((unsigned long long)(sbx[byte(R[0], 5)]) << 40)	^
    ((unsigned long long)(sbx[byte(R[0], 6)]) << 48)	^
    ((unsigned long long)(sbx[byte(R[0], 7)]) << 56);
    temp2 =  (unsigned long long)(sbx[byte(R[4], 0)])		^
    ((unsigned long long)(sbx[byte(R[4], 1)]) <<  8)	^
    ((unsigned long long)(sbx[byte(R[4], 2)]) << 16)	^
    ((unsigned long long)(sbx[byte(R[4], 3)]) << 24)	^
    ((unsigned long long)(sbx[byte(R[4], 4)]) << 32)	^
    ((unsigned long long)(sbx[byte(R[4], 5)]) << 40)	^
    ((unsigned long long)(sbx[byte(R[4], 6)]) << 48)	^
    ((unsigned long long)(sbx[byte(R[4], 7)]) << 56);
    temp1 =  ((unsigned long long)(   byte(temp1,0) )		^
	      (unsigned long long)(F2[byte(temp1,1)])		^
	      (unsigned long long)(FA[byte(temp1,2)])		^
	      (unsigned long long)(F9[byte(temp1,3)])		^
	      (unsigned long long)(F8[byte(temp1,4)])		^
	      (unsigned long long)(   byte(temp1,5) )		^
	      (unsigned long long)(F4[byte(temp1,6)])		^
	      (unsigned long long)(   byte(temp1,7) ))		^
    (((unsigned long long)(   byte(temp1,0) )		^
      (unsigned long long)(   byte(temp1,1) )		^
      (unsigned long long)(F2[byte(temp1,2)])		^
      (unsigned long long)(FA[byte(temp1,3)])		^
      (unsigned long long)(F9[byte(temp1,4)])		^
      (unsigned long long)(F8[byte(temp1,5)])		^
      (unsigned long long)(   byte(temp1,6) )		^
      (unsigned long long)(F4[byte(temp1,7)])) <<  8 )	^
    (((unsigned long long)(F4[byte(temp1,0)])		^
      (unsigned long long)(   byte(temp1,1) )		^
      (unsigned long long)(   byte(temp1,2) )		^
      (unsigned long long)(F2[byte(temp1,3)])		^
      (unsigned long long)(FA[byte(temp1,4)])		^
      (unsigned long long)(F9[byte(temp1,5)])		^
      (unsigned long long)(F8[byte(temp1,6)])		^
      (unsigned long long)(   byte(temp1,7) )) << 16 )	^
    (((unsigned long long)(   byte(temp1,0) )		^
      (unsigned long long)(F4[byte(temp1,1)])		^
      (unsigned long long)(   byte(temp1,2) )		^
      (unsigned long long)(   byte(temp1,3) )		^
      (unsigned long long)(F2[byte(temp1,4)])		^
      (unsigned long long)(FA[byte(temp1,5)])		^
      (unsigned long long)(F9[byte(temp1,6)])		^
      (unsigned long long)(F8[byte(temp1,7)])) << 24 )	^
    (((unsigned long long)(F8[byte(temp1,0)])		^
      (unsigned long long)(   byte(temp1,1) )		^
      (unsigned long long)(F4[byte(temp1,2)])		^
      (unsigned long long)(   byte(temp1,3) )		^
      (unsigned long long)(   byte(temp1,4) )		^
      (unsigned long long)(F2[byte(temp1,5)])		^
      (unsigned long long)(FA[byte(temp1,6)])		^
      (unsigned long long)(F9[byte(temp1,7)])) << 32 )	^
    (((unsigned long long)(F9[byte(temp1,0)])		^
      (unsigned long long)(F8[byte(temp1,1)])		^
      (unsigned long long)(   byte(temp1,2) )		^
      (unsigned long long)(F4[byte(temp1,3)])		^
      (unsigned long long)(   byte(temp1,4) )		^
      (unsigned long long)(   byte(temp1,5) )		^
      (unsigned long long)(F2[byte(temp1,6)])		^
      (unsigned long long)(FA[byte(temp1,7)])) << 40 )	^
    (((unsigned long long)(FA[byte(temp1,0)])		^
      (unsigned long long)(F9[byte(temp1,1)])		^
      (unsigned long long)(F8[byte(temp1,2)])		^
      (unsigned long long)(   byte(temp1,3) )		^
      (unsigned long long)(F4[byte(temp1,4)])		^
      (unsigned long long)(   byte(temp1,5) )		^
      (unsigned long long)(   byte(temp1,6) )		^
      (unsigned long long)(F2[byte(temp1,7)])) << 48 )	^
    (((unsigned long long)(F2[byte(temp1,0)])		^
      (unsigned long long)(FA[byte(temp1,1)])		^
      (unsigned long long)(F9[byte(temp1,2)])		^
      (unsigned long long)(F8[byte(temp1,3)])		^
      (unsigned long long)(   byte(temp1,4) )		^
      (unsigned long long)(F4[byte(temp1,5)])		^
      (unsigned long long)(   byte(temp1,6) )		^
      (unsigned long long)(   byte(temp1,7) )) << 56 );
    temp2 =  ((unsigned long long)(   byte(temp2,0) )		^
	      (unsigned long long)(F2[byte(temp2,1)])		^
	      (unsigned long long)(FA[byte(temp2,2)])		^
	      (unsigned long long)(F9[byte(temp2,3)])		^
	      (unsigned long long)(F8[byte(temp2,4)])		^
	      (unsigned long long)(   byte(temp2,5) )		^
	      (unsigned long long)(F4[byte(temp2,6)])		^
	      (unsigned long long)(   byte(temp2,7) ))		^
    (((unsigned long long)(   byte(temp2,0) )		^
      (unsigned long long)(   byte(temp2,1) )		^
      (unsigned long long)(F2[byte(temp2,2)])		^
      (unsigned long long)(FA[byte(temp2,3)])		^
      (unsigned long long)(F9[byte(temp2,4)])		^
      (unsigned long long)(F8[byte(temp2,5)])		^
      (unsigned long long)(   byte(temp2,6) )		^
      (unsigned long long)(F4[byte(temp2,7)])) <<  8 )	^
    (((unsigned long long)(F4[byte(temp2,0)])		^
      (unsigned long long)(   byte(temp2,1) )		^
      (unsigned long long)(   byte(temp2,2) )		^
      (unsigned long long)(F2[byte(temp2,3)])		^
      (unsigned long long)(FA[byte(temp2,4)])		^
      (unsigned long long)(F9[byte(temp2,5)])		^
      (unsigned long long)(F8[byte(temp2,6)])		^
      (unsigned long long)(   byte(temp2,7) )) << 16 )	^
    (((unsigned long long)(   byte(temp2,0) )		^
      (unsigned long long)(F4[byte(temp2,1)])		^
      (unsigned long long)(   byte(temp2,2) )		^
      (unsigned long long)(   byte(temp2,3) )		^
      (unsigned long long)(F2[byte(temp2,4)])		^
      (unsigned long long)(FA[byte(temp2,5)])		^
      (unsigned long long)(F9[byte(temp2,6)])		^
      (unsigned long long)(F8[byte(temp2,7)])) << 24 )	^
    (((unsigned long long)(F8[byte(temp2,0)])		^
      (unsigned long long)(   byte(temp2,1) )		^
      (unsigned long long)(F4[byte(temp2,2)])		^
      (unsigned long long)(   byte(temp2,3) )		^
      (unsigned long long)(   byte(temp2,4) )		^
      (unsigned long long)(F2[byte(temp2,5)])		^
      (unsigned long long)(FA[byte(temp2,6)])		^
      (unsigned long long)(F9[byte(temp2,7)])) << 32 )	^
    (((unsigned long long)(F9[byte(temp2,0)])		^
      (unsigned long long)(F8[byte(temp2,1)])		^
      (unsigned long long)(   byte(temp2,2) )		^
      (unsigned long long)(F4[byte(temp2,3)])		^
      (unsigned long long)(   byte(temp2,4) )		^
      (unsigned long long)(   byte(temp2,5) )		^
      (unsigned long long)(F2[byte(temp2,6)])		^
      (unsigned long long)(FA[byte(temp2,7)])) << 40 )	^
    (((unsigned long long)(FA[byte(temp2,0)])		^
      (unsigned long long)(F9[byte(temp2,1)])		^
      (unsigned long long)(F8[byte(temp2,2)])		^
      (unsigned long long)(   byte(temp2,3) )		^
      (unsigned long long)(F4[byte(temp2,4)])		^
      (unsigned long long)(   byte(temp2,5) )		^
      (unsigned long long)(   byte(temp2,6) )		^
      (unsigned long long)(F2[byte(temp2,7)])) << 48 )	^
    (((unsigned long long)(F2[byte(temp2,0)])		^
      (unsigned long long)(FA[byte(temp2,1)])		^
      (unsigned long long)(F9[byte(temp2,2)])		^
      (unsigned long long)(F8[byte(temp2,3)])		^
      (unsigned long long)(   byte(temp2,4) )		^
      (unsigned long long)(F4[byte(temp2,5)])		^
      (unsigned long long)(   byte(temp2,6) )		^
      (unsigned long long)(   byte(temp2,7) )) << 56 );

    R[1] ^= temp1;
    R[2] ^= ROTL_QWORD(temp1, 29);
    R[3] ^= ROTL_QWORD(temp1, 41);
    R[5] ^= temp2;
    R[6] ^= ROTL_QWORD(temp2, 53);
    R[7] ^= ROTL_QWORD(temp2, 13);

    temp1=R[7];
    R[7]=R[6];
    R[6]=R[5];
    R[5]=R[4];
    R[4]=R[3];
    R[3]=R[2];
    R[2]=R[1];
    R[1]=R[0];
    R[0]=temp1;
}

static inline void _arirang_Compression256(hash_state *hs)
{
    int i;
    unsigned int R[8], W[32];

    hs->arirang.workingvar[0] ^= ((unsigned int*)hs->arirang.counter)[1];
    hs->arirang.workingvar[4] ^= ((unsigned int*)hs->arirang.counter)[0];

    for (i = 0; i < 16; i++){
	W[i] = GetData(((unsigned int*)hs->arirang.block)[i]);
    }

    W[16] = ROTL_DWORD((W[ 9] ^ W[11] ^ W[13] ^ W[15] ^ K256[ 0]),  5);
    W[17] = ROTL_DWORD((W[ 8] ^ W[10] ^ W[12] ^ W[14] ^ K256[ 1]), 11);
    W[18] = ROTL_DWORD((W[ 1] ^ W[ 3] ^ W[ 5] ^ W[ 7] ^ K256[ 2]), 19);
    W[19] = ROTL_DWORD((W[ 0] ^ W[ 2] ^ W[ 4] ^ W[ 6] ^ K256[ 3]), 31);

    W[20] = ROTL_DWORD((W[14] ^ W[ 4] ^ W[10] ^ W[ 0] ^ K256[ 4]),  5);
    W[21] = ROTL_DWORD((W[11] ^ W[ 1] ^ W[ 7] ^ W[13] ^ K256[ 5]), 11);
    W[22] = ROTL_DWORD((W[ 6] ^ W[12] ^ W[ 2] ^ W[ 8] ^ K256[ 6]), 19);
    W[23] = ROTL_DWORD((W[ 3] ^ W[ 9] ^ W[15] ^ W[ 5] ^ K256[ 7]), 31);

    W[24] = ROTL_DWORD((W[13] ^ W[15] ^ W[ 1] ^ W[ 3] ^ K256[ 8]),  5);
    W[25] = ROTL_DWORD((W[ 4] ^ W[ 6] ^ W[ 8] ^ W[10] ^ K256[ 9]), 11);
    W[26] = ROTL_DWORD((W[ 5] ^ W[ 7] ^ W[ 9] ^ W[11] ^ K256[10]), 19);
    W[27] = ROTL_DWORD((W[12] ^ W[14] ^ W[ 0] ^ W[ 2] ^ K256[11]), 31);

    W[28] = ROTL_DWORD((W[10] ^ W[ 0] ^ W[ 6] ^ W[12] ^ K256[12]),  5);
    W[29] = ROTL_DWORD((W[15] ^ W[ 5] ^ W[11] ^ W[ 1] ^ K256[13]), 11);
    W[30] = ROTL_DWORD((W[ 2] ^ W[ 8] ^ W[14] ^ W[ 4] ^ K256[14]), 19);
    W[31] = ROTL_DWORD((W[ 7] ^ W[13] ^ W[ 3] ^ W[ 9] ^ K256[15]), 31);

    for(i=0;i<8;i++){
	R[i] = (unsigned int)hs->arirang.workingvar[i];
    }

    _step256(R, W[16], W[17]);
    _step256(R, W[ 0], W[ 1]);
    _step256(R, W[ 2], W[ 3]);
    _step256(R, W[ 4], W[ 5]);
    _step256(R, W[ 6], W[ 7]);
    _step256(R, W[18], W[19]);
    _step256(R, W[ 8], W[ 9]);
    _step256(R, W[10], W[11]);
    _step256(R, W[12], W[13]);
    _step256(R, W[14], W[15]);

    _step256(R, W[20], W[21]);
    _step256(R, W[ 3], W[ 6]);
    _step256(R, W[ 9], W[12]);
    _step256(R, W[15], W[ 2]);
    _step256(R, W[ 5], W[ 8]);
    _step256(R, W[22], W[23]);
    _step256(R, W[11], W[14]);
    _step256(R, W[ 1], W[ 4]);
    _step256(R, W[ 7], W[10]);
    _step256(R, W[13], W[ 0]);

    for(i=0;i<8;i++){
	R[i] ^= hs->arirang.workingvar[i];
    }

    _step256(R, W[24], W[25]);
    _step256(R, W[12], W[ 5]);
    _step256(R, W[14], W[ 7]);
    _step256(R, W[ 0], W[ 9]);
    _step256(R, W[ 2], W[11]);
    _step256(R, W[26], W[27]);
    _step256(R, W[ 4], W[13]);
    _step256(R, W[ 6], W[15]);
    _step256(R, W[ 8], W[ 1]);
    _step256(R, W[10], W[ 3]);

    _step256(R, W[28], W[29]);
    _step256(R, W[ 7], W[ 2]);
    _step256(R, W[13], W[ 8]);
    _step256(R, W[ 3], W[14]);
    _step256(R, W[ 9], W[ 4]);
    _step256(R, W[30], W[31]);
    _step256(R, W[15], W[10]);
    _step256(R, W[ 5], W[ 0]);
    _step256(R, W[11], W[ 6]);
    _step256(R, W[ 1], W[12]);

    for(i=0;i<8;i++){
	hs->arirang.workingvar[i] ^= R[i];
    }

    hs->arirang.counter[0]++;
}

static inline void _arirang_Compression512(hash_state *hs)
{
    int i;
    unsigned long long R[8], W[32];

    hs->arirang.workingvar[0] ^= hs->arirang.counter[1];
    hs->arirang.workingvar[4] ^= hs->arirang.counter[0];

    for (i = 0; i < 16; i++){
	W[i] =	 (unsigned long long)(GetData(((unsigned int*)hs->arirang.block)[2*i+1])) |
	((unsigned long long)(GetData(((unsigned int*)hs->arirang.block)[2*i])) << 32);
    }

    W[16] = ROTL_QWORD((W[ 9] ^ W[11] ^ W[13] ^ W[15] ^ K512[ 0]), 11);
    W[17] = ROTL_QWORD((W[ 8] ^ W[10] ^ W[12] ^ W[14] ^ K512[ 1]), 23);
    W[18] = ROTL_QWORD((W[ 1] ^ W[ 3] ^ W[ 5] ^ W[ 7] ^ K512[ 2]), 37);
    W[19] = ROTL_QWORD((W[ 0] ^ W[ 2] ^ W[ 4] ^ W[ 6] ^ K512[ 3]), 59);

    W[20] = ROTL_QWORD((W[14] ^ W[ 4] ^ W[10] ^ W[ 0] ^ K512[ 4]), 11);
    W[21] = ROTL_QWORD((W[11] ^ W[ 1] ^ W[ 7] ^ W[13] ^ K512[ 5]), 23);
    W[22] = ROTL_QWORD((W[ 6] ^ W[12] ^ W[ 2] ^ W[ 8] ^ K512[ 6]), 37);
    W[23] = ROTL_QWORD((W[ 3] ^ W[ 9] ^ W[15] ^ W[ 5] ^ K512[ 7]), 59);

    W[24] = ROTL_QWORD((W[13] ^ W[15] ^ W[ 1] ^ W[ 3] ^ K512[ 8]), 11);
    W[25] = ROTL_QWORD((W[ 4] ^ W[ 6] ^ W[ 8] ^ W[10] ^ K512[ 9]), 23);
    W[26] = ROTL_QWORD((W[ 5] ^ W[ 7] ^ W[ 9] ^ W[11] ^ K512[10]), 37);
    W[27] = ROTL_QWORD((W[12] ^ W[14] ^ W[ 0] ^ W[ 2] ^ K512[11]), 59);

    W[28] = ROTL_QWORD((W[10] ^ W[ 0] ^ W[ 6] ^ W[12] ^ K512[12]), 11);
    W[29] = ROTL_QWORD((W[15] ^ W[ 5] ^ W[11] ^ W[ 1] ^ K512[13]), 23);
    W[30] = ROTL_QWORD((W[ 2] ^ W[ 8] ^ W[14] ^ W[ 4] ^ K512[14]), 37);
    W[31] = ROTL_QWORD((W[ 7] ^ W[13] ^ W[ 3] ^ W[ 9] ^ K512[15]), 59);

    for(i=0;i<8;i++){
	R[i] = hs->arirang.workingvar[i];
    }

    _step512(R, W[16], W[17]);
    _step512(R, W[ 0], W[ 1]);
    _step512(R, W[ 2], W[ 3]);
    _step512(R, W[ 4], W[ 5]);
    _step512(R, W[ 6], W[ 7]);
    _step512(R, W[18], W[19]);
    _step512(R, W[ 8], W[ 9]);
    _step512(R, W[10], W[11]);
    _step512(R, W[12], W[13]);
    _step512(R, W[14], W[15]);

    _step512(R, W[20], W[21]);
    _step512(R, W[ 3], W[ 6]);
    _step512(R, W[ 9], W[12]);
    _step512(R, W[15], W[ 2]);
    _step512(R, W[ 5], W[ 8]);
    _step512(R, W[22], W[23]);
    _step512(R, W[11], W[14]);
    _step512(R, W[ 1], W[ 4]);
    _step512(R, W[ 7], W[10]);
    _step512(R, W[13], W[ 0]);

    for(i=0;i<8;i++){
	R[i] ^= hs->arirang.workingvar[i];
    }

    _step512(R, W[24], W[25]);
    _step512(R, W[12], W[ 5]);
    _step512(R, W[14], W[ 7]);
    _step512(R, W[ 0], W[ 9]);
    _step512(R, W[ 2], W[11]);
    _step512(R, W[26], W[27]);
    _step512(R, W[ 4], W[13]);
    _step512(R, W[ 6], W[15]);
    _step512(R, W[ 8], W[ 1]);
    _step512(R, W[10], W[ 3]);

    _step512(R, W[28], W[29]);
    _step512(R, W[ 7], W[ 2]);
    _step512(R, W[13], W[ 8]);
    _step512(R, W[ 3], W[14]);
    _step512(R, W[ 9], W[ 4]);
    _step512(R, W[30], W[31]);
    _step512(R, W[15], W[10]);
    _step512(R, W[ 5], W[ 0]);
    _step512(R, W[11], W[ 6]);
    _step512(R, W[ 1], W[12]);

    for(i=0;i<8;i++){
	hs->arirang.workingvar[i] ^= R[i];
    }

    hs->arirang.counter[0]++;
    if(hs->arirang.counter[0] == 0){
	hs->arirang.counter[1]++;
    }
}

static inline int _arirang_init(hash_state *hs, int hashbitlen)
{
    if ((hashbitlen != 224) && (hashbitlen != 256) && (hashbitlen != 384) && (hashbitlen != 512)){
	return NBSCrypto_ERROR;
    }

    _gen_tabs();

    hs->arirang.hashbitlen = hashbitlen;
    hs->arirang.counter[0] = hs->arirang.counter[1] = 0;
    hs->arirang.count[0] = hs->arirang.count[1] = 0;

    if(hashbitlen == 224){
	hs->arirang.workingvar[0] = 0xcbbb9d5d;
	hs->arirang.workingvar[1] = 0x629a292a;
	hs->arirang.workingvar[2] = 0x9159015a;
	hs->arirang.workingvar[3] = 0x152fecd8;
	hs->arirang.workingvar[4] = 0x67332667;
	hs->arirang.workingvar[5] = 0x8eb44a87;
	hs->arirang.workingvar[6] = 0xdb0c2e0d;
	hs->arirang.workingvar[7] = 0x47b5481d;
	hs->arirang.blocklen=64;
    }
    else if(hashbitlen == 256){
	hs->arirang.workingvar[0] = 0x6a09e667;
	hs->arirang.workingvar[1] = 0xbb67ae85;
	hs->arirang.workingvar[2] = 0x3c6ef372;
	hs->arirang.workingvar[3] = 0xa54ff53a;
	hs->arirang.workingvar[4] = 0x510e527f;
	hs->arirang.workingvar[5] = 0x9b05688c;
	hs->arirang.workingvar[6] = 0x1f83d9ab;
	hs->arirang.workingvar[7] = 0x5be0cd19;
	hs->arirang.blocklen=64;

    }
    else if(hashbitlen == 384){
	hs->arirang.workingvar[0]=0xcbbb9d5dc1059ed8ULL;
	hs->arirang.workingvar[1]=0x629a292a367cd507ULL;
	hs->arirang.workingvar[2]=0x9159015a3070dd17ULL;
	hs->arirang.workingvar[3]=0x152fecd8f70e5939ULL;
	hs->arirang.workingvar[4]=0x67332667ffc00b31ULL;
	hs->arirang.workingvar[5]=0x8eb44a8768581511ULL;
	hs->arirang.workingvar[6]=0xdb0c2e0d64f98fa7ULL;
	hs->arirang.workingvar[7]=0x47b5481dbefa4fa4ULL;
	hs->arirang.blocklen=128;

    }
    else if(hashbitlen == 512){
	hs->arirang.workingvar[0]=0x6a09e667f3bcc908ULL;
	hs->arirang.workingvar[1]=0xbb67ae8584caa73bULL;
	hs->arirang.workingvar[2]=0x3c6ef372fe94f82bULL;
	hs->arirang.workingvar[3]=0xa54ff53a5f1d36f1ULL;
	hs->arirang.workingvar[4]=0x510e527fade682d1ULL;
	hs->arirang.workingvar[5]=0x9b05688c2b3e6c1fULL;
	hs->arirang.workingvar[6]=0x1f83d9abfb41bd6bULL;
	hs->arirang.workingvar[7]=0x5be0cd19137e2179ULL;
	hs->arirang.blocklen=128;
    }
    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS

int arirang_224_init(hash_state *hs){return _arirang_init(hs, 224);}
int arirang_256_init(hash_state *hs){return _arirang_init(hs, 256);}
int arirang_384_init(hash_state *hs){return _arirang_init(hs, 384);}
int arirang_512_init(hash_state *hs){return _arirang_init(hs, 512);}

int arirang_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned int RemainedLen, PartLen;
    unsigned long long databytelen, temp;

    hs->arirang.remainderbit = inlen & 7;

    databytelen = ( inlen >> 3) + (hs->arirang.remainderbit != 0);
    RemainedLen = (hs->arirang.count[0] >> 3) % hs->arirang.blocklen;
    PartLen = hs->arirang.blocklen - RemainedLen;

    temp = hs->arirang.count[0] + (databytelen << 3);
    if(temp < hs->arirang.count[0] ){
	hs->arirang.count[1]++;
    }
    hs->arirang.count[0]=temp;

    if ((databytelen > PartLen) || ((databytelen == PartLen) && (hs->arirang.remainderbit == 0)) ) {
	memcpy(hs->arirang.block + RemainedLen, in, (int)PartLen);
	if(hs->arirang.hashbitlen <257){
	    _arirang_Compression256(hs);
	}else{
	    _arirang_Compression512(hs);
	}

	in += PartLen;
	databytelen -= PartLen;
	RemainedLen = 0;

	while( (databytelen > hs->arirang.blocklen) || ((databytelen == hs->arirang.blocklen) && (hs->arirang.remainderbit == 0)) ) {
	    memcpy((unsigned char *)hs->arirang.block, in, (int)hs->arirang.blocklen);
	    if(hs->arirang.hashbitlen <257){
		_arirang_Compression256(hs);
	    }else{
		_arirang_Compression512(hs);
	    }

	    in += hs->arirang.blocklen;
	    databytelen -= hs->arirang.blocklen;
	}
    }

    memcpy((unsigned char *)hs->arirang.block + RemainedLen, in, (int)databytelen);

    return NBSCrypto_OK;
}

int arirang_done(hash_state *hs, unsigned char *out)
{
    unsigned int i, dwIndex;
    unsigned int temp=(hs->arirang.blocklen >> 3);
    unsigned long long count[2];

    if(hs->arirang.remainderbit){
	count[0] = hs->arirang.count[0] + hs->arirang.remainderbit - 8;
	count[1] = hs->arirang.count[1];
	dwIndex = ((count[0] + (hs->arirang.blocklen<<3) ) >> 3) % hs->arirang.blocklen;
	hs->arirang.block[dwIndex] &= 0xff-(1<<(8-hs->arirang.remainderbit))+1;
	hs->arirang.block[dwIndex++] ^= 0x80>>(hs->arirang.remainderbit);
    }else{
	count[0] = hs->arirang.count[0];
	count[1] = hs->arirang.count[1];
	dwIndex = (count[0] >> 3) % hs->arirang.blocklen;
	hs->arirang.block[dwIndex++] = 0x80;
    }

    if (dwIndex > (hs->arirang.blocklen - temp)){
	memset((unsigned char *)hs->arirang.block + dwIndex, 0, (int)(hs->arirang.blocklen - dwIndex));
	if(hs->arirang.hashbitlen <257){
	    _arirang_Compression256(hs);
	}else{
	    _arirang_Compression512(hs);
	}
	memset((unsigned char *)hs->arirang.block, 0, (int)hs->arirang.blocklen - temp);
    }else{
	memset((unsigned char *)hs->arirang.block + dwIndex, 0, (int)(hs->arirang.blocklen - dwIndex - temp));

	count[0] = ENDIAN_REVERSE_DWORD(((unsigned int*)count)[1]) |
	((unsigned long long)(ENDIAN_REVERSE_DWORD(((unsigned int*)count)[0])) << 32);
	count[1] = ENDIAN_REVERSE_DWORD(((unsigned int*)count)[3]) |
	((unsigned long long)(ENDIAN_REVERSE_DWORD(((unsigned int*)count)[2])) << 32);
    }

    if(hs->arirang.hashbitlen > 257){
	((unsigned long long *)hs->arirang.block)[hs->arirang.blocklen/8-2] = count[1];
	((unsigned long long *)hs->arirang.block)[hs->arirang.blocklen/8-1] = count[0];
	hs->arirang.counter[1]=0xb7e151628aed2a6aULL;
	hs->arirang.counter[0]=0xbf7158809cf4f3c7ULL;
    }
    else{
	((unsigned long long *)hs->arirang.block)[hs->arirang.blocklen/8-1] = count[0];
	hs->arirang.counter[0]=0xb7e151628aed2a6aULL;
    }

    if(hs->arirang.hashbitlen <257){
	_arirang_Compression256(hs);
    }else{
	_arirang_Compression512(hs);
    }

    if(hs->arirang.hashbitlen <257){
	for (i = 0; i < (hs->arirang.hashbitlen >> 3); i += 4){
	    BIG_D2B((hs->arirang.workingvar)[(i*2) / 8], &(out[i]));
	}
    }else{
	for (i = 0; i < (hs->arirang.hashbitlen >> 3); i += 8){
	    BIG_Q2B((hs->arirang.workingvar)[i / 8], &(out[i]));
	}
    }

    return NBSCrypto_OK;
}
