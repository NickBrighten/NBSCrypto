//
//	bluemidnightwish.c
//	Authors / Developers		: Danilo Gligoroski, Vlastimil Klima, Svein Johan Knapskog
//					  Mohamed El-Hadedy, Jørn Amundsen, Stig Frode Mjølsnes
//	Last Modified (Original)	: 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor bluemidnightwish_224_desc =
{
    "bluemidnightwish-224",
    10060224,
    28,
    64,
    &bluemidnightwish_224_init,
    &bluemidnightwish_process,
    &bluemidnightwish_done,
    NULL
};

const struct hash_descriptor bluemidnightwish_256_desc =
{
    "bluemidnightwish-256",
    10060256,
    32,
    64,
    &bluemidnightwish_256_init,
    &bluemidnightwish_process,
    &bluemidnightwish_done,
    NULL
};

const struct hash_descriptor bluemidnightwish_384_desc =
{
    "bluemidnightwish-384",
    10060384,
    48,
    64,
    &bluemidnightwish_384_init,
    &bluemidnightwish_process,
    &bluemidnightwish_done,
    NULL
};

const struct hash_descriptor bluemidnightwish_512_desc =
{
    "bluemidnightwish-512",
    10060512,
    64,
    64,
    &bluemidnightwish_512_init,
    &bluemidnightwish_process,
    &bluemidnightwish_done,
    NULL
};




#pragma mark - DEFINES

#define EXPAND_1_ROUNDS 2
#define EXPAND_2_ROUNDS 14

#define rotl32(x,n) (((x) << n) | ((x) >> (32 - n)))
#define rotr32(x,n) (((x) >> n) | ((x) << (32 - n)))
#define rotl64(x,n) (((x) << n) | ((x) >> (64 - n)))
#define rotr64(x,n) (((x) >> n) | ((x) << (64 - n)))

#define shl(x,n) ((x) << n)
#define shr(x,n) ((x) >> n)

#define s32_0(x) (shr((x), 1) ^ shl((x), 3) ^ rotl32((x),  4) ^ rotl32((x), 19))
#define s32_1(x) (shr((x), 1) ^ shl((x), 2) ^ rotl32((x),  8) ^ rotl32((x), 23))
#define s32_2(x) (shr((x), 2) ^ shl((x), 1) ^ rotl32((x), 12) ^ rotl32((x), 25))
#define s32_3(x) (shr((x), 2) ^ shl((x), 2) ^ rotl32((x), 15) ^ rotl32((x), 29))
#define s32_4(x) (shr((x), 1) ^ (x))
#define s32_5(x) (shr((x), 2) ^ (x))
#define r32_01(x) rotl32((x),  3)
#define r32_02(x) rotl32((x),  7)
#define r32_03(x) rotl32((x), 13)
#define r32_04(x) rotl32((x), 16)
#define r32_05(x) rotl32((x), 19)
#define r32_06(x) rotl32((x), 23)
#define r32_07(x) rotl32((x), 27)

#define s64_0(x)  (shr((x), 1) ^ shl((x), 3) ^ rotl64((x),  4) ^ rotl64((x), 37))
#define s64_1(x)  (shr((x), 1) ^ shl((x), 2) ^ rotl64((x), 13) ^ rotl64((x), 43))
#define s64_2(x)  (shr((x), 2) ^ shl((x), 1) ^ rotl64((x), 19) ^ rotl64((x), 53))
#define s64_3(x)  (shr((x), 2) ^ shl((x), 2) ^ rotl64((x), 28) ^ rotl64((x), 59))
#define s64_4(x)  (shr((x), 1) ^ (x))
#define s64_5(x)  (shr((x), 2) ^ (x))
#define r64_01(x) rotl64((x),  5)
#define r64_02(x) rotl64((x), 11)
#define r64_03(x) rotl64((x), 27)
#define r64_04(x) rotl64((x), 32)
#define r64_05(x) rotl64((x), 37)
#define r64_06(x) rotl64((x), 43)
#define r64_07(x) rotl64((x), 53)

#define hashState224(x) ((x)->bluemidnightwish.pipe->p256)
#define hashState256(x) ((x)->bluemidnightwish.pipe->p256)
#define hashState384(x) ((x)->bluemidnightwish.pipe->p512)
#define hashState512(x) ((x)->bluemidnightwish.pipe->p512)

const unsigned int i224p2[16] =
{   0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
    0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
    0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f,
    0x30313233, 0x24353637, 0x38393a3b, 0x3c3d3e3f,
};

const unsigned int i256p2[16] =
{   0x40414243, 0x44454647, 0x48494a4b, 0x4c4d4e4f,
    0x50515253, 0x54555657, 0x58595a5b, 0x5c5d5e5f,
    0x60616263, 0x64656667, 0x68696a6b, 0x6c6d6e6f,
    0x70717273, 0x74757677, 0x78797a7b, 0x7c7d7e7f,
};

const unsigned long long i384p2[16] =
{
    0x0001020304050607, 0x08090a0b0c0d0e0f, 0x1011121314151617, 0x18191a1b1c1d1e1f,
    0x2021222324252627, 0x28292a2b2c2d2e2f, 0x3031323324353637, 0x38393a3b3c3d3e3f,
    0x4041424344454647, 0x48494a4b4c4d4e4f, 0x5051525354555657, 0x58595a5b5c5d5e5f,
    0x6061626364656667, 0x68696a6b6c6d6e6f, 0x7071727374757677, 0x78797a7b7c7d7e7f
};

const unsigned long long i512p2[16] =
{
    0x8081828384858687, 0x88898a8b8c8d8e8f, 0x9091929394959697, 0x98999a9b9c9d9e9f,
    0xa0a1a2a3a4a5a6a7, 0xa8a9aaabacadaeaf, 0xb0b1b2b3b4b5b6b7, 0xb8b9babbbcbdbebf,
    0xc0c1c2c3c4c5c6c7, 0xc8c9cacbcccdcecf, 0xd0d1d2d3d4d5d6d7, 0xd8d9dadbdcdddedf,
    0xe0e1e2e3e4e5e6e7, 0xe8e9eaebecedeeef, 0xf0f1f2f3f4f5f6f7, 0xf8f9fafbfcfdfeff
};




#pragma mark - INLINE

static inline unsigned int _expand32_1(int i, unsigned int *M32, unsigned int *Q)
{
    return (  s32_1(Q[i - 16])      	+ s32_2(Q[i - 15])   + s32_3(Q[i - 14]  ) + s32_0(Q[i - 13] )
	    + s32_1(Q[i - 12])      	+ s32_2(Q[i - 11])   + s32_3(Q[i - 10]  ) + s32_0(Q[i -  9] )
	    + s32_1(Q[i -  8])      	+ s32_2(Q[i -  7])   + s32_3(Q[i -  6]  ) + s32_0(Q[i -  5] )
	    + s32_1(Q[i -  4])      	+ s32_2(Q[i -  3])   + s32_3(Q[i -  2]  ) + s32_0(Q[i -  1] )
	    + i*(0x05555555)      	+ M32[(i-16)%16]     + M32[(i-13)%16]     - M32[(i-6)%16]);
}

static inline unsigned int _expand32_2(int i, unsigned int *M32, unsigned int *Q)
{
    return (  Q[i - 16]             	+ r32_01(Q[i - 15])  +        Q[i - 14]   + r32_02(Q[i - 13])
	    + Q[i - 12]             	+ r32_03(Q[i - 11])  +        Q[i - 10]   + r32_04(Q[i -  9])
	    + Q[i -  8]             	+ r32_05(Q[i -  7])  +        Q[i -  6]   + r32_06(Q[i -  5])
	    + Q[i -  4]             	+ r32_07(Q[i -  3])  + s32_5( Q[i -  2] ) + s32_4( Q[i -  1])
	    + i*(0x05555555)		+ M32[(i-16)%16]     + M32[(i-13)%16]     - M32[(i-6)%16]);
}

static inline unsigned long long _expand64_1(int i, unsigned long long *M64, unsigned long long *Q)
{
    return (  s64_1(Q[i - 16])          + s64_2(Q[i - 15])   + s64_3(Q[i - 14]  ) + s64_0(Q[i - 13] )
	    + s64_1(Q[i - 12])          + s64_2(Q[i - 11])   + s64_3(Q[i - 10]  ) + s64_0(Q[i -  9] )
	    + s64_1(Q[i -  8])          + s64_2(Q[i -  7])   + s64_3(Q[i -  6]  ) + s64_0(Q[i -  5] )
	    + s64_1(Q[i -  4])          + s64_2(Q[i -  3])   + s64_3(Q[i -  2]  ) + s64_0(Q[i -  1] )
	    + i*(0x0555555555555555) + M64[(i-16)%16]     + M64[(i-13)%16]     - M64[(i-6)%16]);
}

static inline unsigned long long _expand64_2(int i, unsigned long long *M64, unsigned long long *Q)
{
    return (  Q[i - 16]                 + r64_01(Q[i - 15])  +        Q[i - 14]   + r64_02(Q[i - 13])
	    + Q[i - 12]                 + r64_03(Q[i - 11])  +        Q[i - 10]   + r64_04(Q[i -  9])
	    + Q[i -  8]                 + r64_05(Q[i -  7])  +        Q[i -  6]   + r64_06(Q[i -  5])
	    + Q[i -  4]                 + r64_07(Q[i -  3])  + s64_5( Q[i -  2] ) + s64_4( Q[i -  1])
	    + i*(0x0555555555555555) + M64[(i-16)%16]     + M64[(i-13)%16]     - M64[(i-6)%16]);
}

static inline void _compression256(unsigned int *M32, unsigned int *H)
{
    int i;
    unsigned int XL32, XH32, W[32], Q[32];

    W[ 0] = (M32[ 5] ^ H[ 5]) - (M32[ 7] ^ H[ 7]) + (M32[10] ^ H[10]) + (M32[13] ^ H[13]) + (M32[14] ^ H[14]);
    W[ 1] = (M32[ 6] ^ H[ 6]) - (M32[ 8] ^ H[ 8]) + (M32[11] ^ H[11]) + (M32[14] ^ H[14]) - (M32[15] ^ H[15]);
    W[ 2] = (M32[ 0] ^ H[ 0]) + (M32[ 7] ^ H[ 7]) + (M32[ 9] ^ H[ 9]) - (M32[12] ^ H[12]) + (M32[15] ^ H[15]);
    W[ 3] = (M32[ 0] ^ H[ 0]) - (M32[ 1] ^ H[ 1]) + (M32[ 8] ^ H[ 8]) - (M32[10] ^ H[10]) + (M32[13] ^ H[13]);
    W[ 4] = (M32[ 1] ^ H[ 1]) + (M32[ 2] ^ H[ 2]) + (M32[ 9] ^ H[ 9]) - (M32[11] ^ H[11]) - (M32[14] ^ H[14]);
    W[ 5] = (M32[ 3] ^ H[ 3]) - (M32[ 2] ^ H[ 2]) + (M32[10] ^ H[10]) - (M32[12] ^ H[12]) + (M32[15] ^ H[15]);
    W[ 6] = (M32[ 4] ^ H[ 4]) - (M32[ 0] ^ H[ 0]) - (M32[ 3] ^ H[ 3]) - (M32[11] ^ H[11]) + (M32[13] ^ H[13]);
    W[ 7] = (M32[ 1] ^ H[ 1]) - (M32[ 4] ^ H[ 4]) - (M32[ 5] ^ H[ 5]) - (M32[12] ^ H[12]) - (M32[14] ^ H[14]);
    W[ 8] = (M32[ 2] ^ H[ 2]) - (M32[ 5] ^ H[ 5]) - (M32[ 6] ^ H[ 6]) + (M32[13] ^ H[13]) - (M32[15] ^ H[15]);
    W[ 9] = (M32[ 0] ^ H[ 0]) - (M32[ 3] ^ H[ 3]) + (M32[ 6] ^ H[ 6]) - (M32[ 7] ^ H[ 7]) + (M32[14] ^ H[14]);
    W[10] = (M32[ 8] ^ H[ 8]) - (M32[ 1] ^ H[ 1]) - (M32[ 4] ^ H[ 4]) - (M32[ 7] ^ H[ 7]) + (M32[15] ^ H[15]);
    W[11] = (M32[ 8] ^ H[ 8]) - (M32[ 0] ^ H[ 0]) - (M32[ 2] ^ H[ 2]) - (M32[ 5] ^ H[ 5]) + (M32[ 9] ^ H[ 9]);
    W[12] = (M32[ 1] ^ H[ 1]) + (M32[ 3] ^ H[ 3]) - (M32[ 6] ^ H[ 6]) - (M32[ 9] ^ H[ 9]) + (M32[10] ^ H[10]);
    W[13] = (M32[ 2] ^ H[ 2]) + (M32[ 4] ^ H[ 4]) + (M32[ 7] ^ H[ 7]) + (M32[10] ^ H[10]) + (M32[11] ^ H[11]);
    W[14] = (M32[ 3] ^ H[ 3]) - (M32[ 5] ^ H[ 5]) + (M32[ 8] ^ H[ 8]) - (M32[11] ^ H[11]) - (M32[12] ^ H[12]);
    W[15] = (M32[12] ^ H[12]) - (M32[ 4] ^ H[ 4]) - (M32[ 6] ^ H[ 6]) - (M32[ 9] ^ H[ 9]) + (M32[13] ^ H[13]);

    Q[ 0] = s32_0(W[ 0]);
    Q[ 1] = s32_1(W[ 1]);
    Q[ 2] = s32_2(W[ 2]);
    Q[ 3] = s32_3(W[ 3]);
    Q[ 4] = s32_4(W[ 4]);
    Q[ 5] = s32_0(W[ 5]);
    Q[ 6] = s32_1(W[ 6]);
    Q[ 7] = s32_2(W[ 7]);
    Q[ 8] = s32_3(W[ 8]);
    Q[ 9] = s32_4(W[ 9]);
    Q[10] = s32_0(W[10]);
    Q[11] = s32_1(W[11]);
    Q[12] = s32_2(W[12]);
    Q[13] = s32_3(W[13]);
    Q[14] = s32_4(W[14]);
    Q[15] = s32_0(W[15]);

    for (i=0; i<EXPAND_1_ROUNDS; i++){
	Q[i+16] = _expand32_1(i+16, M32, Q);
    }
    for (i=EXPAND_1_ROUNDS; i<EXPAND_1_ROUNDS + EXPAND_2_ROUNDS; i++){
	Q[i+16] = _expand32_2(i+16, M32, Q);
    }

    XL32 = Q[16]^Q[17]^Q[18]^Q[19]^Q[20]^Q[21]^Q[22]^Q[23];
    XH32 = XL32^Q[24]^Q[25]^Q[26]^Q[27]^Q[28]^Q[29]^Q[30]^Q[31];

    H[0] =                    (shl(XH32, 5) ^ shr(Q[16],5) ^ M32[ 0]) + (    XL32    ^ Q[24] ^ Q[ 0]);
    H[1] =                    (shr(XH32, 7) ^ shl(Q[17],8) ^ M32[ 1]) + (    XL32    ^ Q[25] ^ Q[ 1]);
    H[2] =                    (shr(XH32, 5) ^ shl(Q[18],5) ^ M32[ 2]) + (    XL32    ^ Q[26] ^ Q[ 2]);
    H[3] =                    (shr(XH32, 1) ^ shl(Q[19],5) ^ M32[ 3]) + (    XL32    ^ Q[27] ^ Q[ 3]);
    H[4] =                    (shr(XH32, 3) ^     Q[20]    ^ M32[ 4]) + (    XL32    ^ Q[28] ^ Q[ 4]);
    H[5] =                    (shl(XH32, 6) ^ shr(Q[21],6) ^ M32[ 5]) + (    XL32    ^ Q[29] ^ Q[ 5]);
    H[6] =                    (shr(XH32, 4) ^ shl(Q[22],6) ^ M32[ 6]) + (    XL32    ^ Q[30] ^ Q[ 6]);
    H[7] =                    (shr(XH32,11) ^ shl(Q[23],2) ^ M32[ 7]) + (    XL32    ^ Q[31] ^ Q[ 7]);

    H[ 8] = rotl32(H[4], 9) + (    XH32     ^     Q[24]    ^ M32[ 8]) + (shl(XL32,8) ^ Q[23] ^ Q[ 8]);
    H[ 9] = rotl32(H[5],10) + (    XH32     ^     Q[25]    ^ M32[ 9]) + (shr(XL32,6) ^ Q[16] ^ Q[ 9]);
    H[10] = rotl32(H[6],11) + (    XH32     ^     Q[26]    ^ M32[10]) + (shl(XL32,6) ^ Q[17] ^ Q[10]);
    H[11] = rotl32(H[7],12) + (    XH32     ^     Q[27]    ^ M32[11]) + (shl(XL32,4) ^ Q[18] ^ Q[11]);
    H[12] = rotl32(H[0],13) + (    XH32     ^     Q[28]    ^ M32[12]) + (shr(XL32,3) ^ Q[19] ^ Q[12]);
    H[13] = rotl32(H[1],14) + (    XH32     ^     Q[29]    ^ M32[13]) + (shr(XL32,4) ^ Q[20] ^ Q[13]);
    H[14] = rotl32(H[2],15) + (    XH32     ^     Q[30]    ^ M32[14]) + (shr(XL32,7) ^ Q[21] ^ Q[14]);
    H[15] = rotl32(H[3],16) + (    XH32     ^     Q[31]    ^ M32[15]) + (shr(XL32,2) ^ Q[22] ^ Q[15]);
}

static inline void _compression512(unsigned long long *M64, unsigned long long *H)
{
    int i;
    unsigned long long XL64, XH64, W[32], Q[32];

    W[ 0] = (M64[ 5] ^ H[ 5]) - (M64[ 7] ^ H[ 7]) + (M64[10] ^ H[10]) + (M64[13] ^ H[13]) + (M64[14] ^ H[14]);
    W[ 1] = (M64[ 6] ^ H[ 6]) - (M64[ 8] ^ H[ 8]) + (M64[11] ^ H[11]) + (M64[14] ^ H[14]) - (M64[15] ^ H[15]);
    W[ 2] = (M64[ 0] ^ H[ 0]) + (M64[ 7] ^ H[ 7]) + (M64[ 9] ^ H[ 9]) - (M64[12] ^ H[12]) + (M64[15] ^ H[15]);
    W[ 3] = (M64[ 0] ^ H[ 0]) - (M64[ 1] ^ H[ 1]) + (M64[ 8] ^ H[ 8]) - (M64[10] ^ H[10]) + (M64[13] ^ H[13]);
    W[ 4] = (M64[ 1] ^ H[ 1]) + (M64[ 2] ^ H[ 2]) + (M64[ 9] ^ H[ 9]) - (M64[11] ^ H[11]) - (M64[14] ^ H[14]);
    W[ 5] = (M64[ 3] ^ H[ 3]) - (M64[ 2] ^ H[ 2]) + (M64[10] ^ H[10]) - (M64[12] ^ H[12]) + (M64[15] ^ H[15]);
    W[ 6] = (M64[ 4] ^ H[ 4]) - (M64[ 0] ^ H[ 0]) - (M64[ 3] ^ H[ 3]) - (M64[11] ^ H[11]) + (M64[13] ^ H[13]);
    W[ 7] = (M64[ 1] ^ H[ 1]) - (M64[ 4] ^ H[ 4]) - (M64[ 5] ^ H[ 5]) - (M64[12] ^ H[12]) - (M64[14] ^ H[14]);
    W[ 8] = (M64[ 2] ^ H[ 2]) - (M64[ 5] ^ H[ 5]) - (M64[ 6] ^ H[ 6]) + (M64[13] ^ H[13]) - (M64[15] ^ H[15]);
    W[ 9] = (M64[ 0] ^ H[ 0]) - (M64[ 3] ^ H[ 3]) + (M64[ 6] ^ H[ 6]) - (M64[ 7] ^ H[ 7]) + (M64[14] ^ H[14]);
    W[10] = (M64[ 8] ^ H[ 8]) - (M64[ 1] ^ H[ 1]) - (M64[ 4] ^ H[ 4]) - (M64[ 7] ^ H[ 7]) + (M64[15] ^ H[15]);
    W[11] = (M64[ 8] ^ H[ 8]) - (M64[ 0] ^ H[ 0]) - (M64[ 2] ^ H[ 2]) - (M64[ 5] ^ H[ 5]) + (M64[ 9] ^ H[ 9]);
    W[12] = (M64[ 1] ^ H[ 1]) + (M64[ 3] ^ H[ 3]) - (M64[ 6] ^ H[ 6]) - (M64[ 9] ^ H[ 9]) + (M64[10] ^ H[10]);
    W[13] = (M64[ 2] ^ H[ 2]) + (M64[ 4] ^ H[ 4]) + (M64[ 7] ^ H[ 7]) + (M64[10] ^ H[10]) + (M64[11] ^ H[11]);
    W[14] = (M64[ 3] ^ H[ 3]) - (M64[ 5] ^ H[ 5]) + (M64[ 8] ^ H[ 8]) - (M64[11] ^ H[11]) - (M64[12] ^ H[12]);
    W[15] = (M64[12] ^ H[12]) - (M64[ 4] ^ H[ 4]) - (M64[ 6] ^ H[ 6]) - (M64[ 9] ^ H[ 9]) + (M64[13] ^ H[13]);

    Q[ 0] = s64_0(W[ 0]);
    Q[ 1] = s64_1(W[ 1]);
    Q[ 2] = s64_2(W[ 2]);
    Q[ 3] = s64_3(W[ 3]);
    Q[ 4] = s64_4(W[ 4]);
    Q[ 5] = s64_0(W[ 5]);
    Q[ 6] = s64_1(W[ 6]);
    Q[ 7] = s64_2(W[ 7]);
    Q[ 8] = s64_3(W[ 8]);
    Q[ 9] = s64_4(W[ 9]);
    Q[10] = s64_0(W[10]);
    Q[11] = s64_1(W[11]);
    Q[12] = s64_2(W[12]);
    Q[13] = s64_3(W[13]);
    Q[14] = s64_4(W[14]);
    Q[15] = s64_0(W[15]);

    for (i=0; i<EXPAND_1_ROUNDS; i++){
	Q[i+16] = _expand64_1(i+16, M64, Q);
    }
    for (i=EXPAND_1_ROUNDS; i<EXPAND_1_ROUNDS + EXPAND_2_ROUNDS; i++){
	Q[i+16] = _expand64_2(i+16, M64, Q);
    }

    XL64 = Q[16]^Q[17]^Q[18]^Q[19]^Q[20]^Q[21]^Q[22]^Q[23];
    XH64 = XL64^Q[24]^Q[25]^Q[26]^Q[27]^Q[28]^Q[29]^Q[30]^Q[31];

    H[0] =                    (shl(XH64, 5) ^ shr(Q[16],5) ^ M64[ 0]) + (    XL64    ^ Q[24] ^ Q[ 0]);
    H[1] =                    (shr(XH64, 7) ^ shl(Q[17],8) ^ M64[ 1]) + (    XL64    ^ Q[25] ^ Q[ 1]);
    H[2] =                    (shr(XH64, 5) ^ shl(Q[18],5) ^ M64[ 2]) + (    XL64    ^ Q[26] ^ Q[ 2]);
    H[3] =                    (shr(XH64, 1) ^ shl(Q[19],5) ^ M64[ 3]) + (    XL64    ^ Q[27] ^ Q[ 3]);
    H[4] =                    (shr(XH64, 3) ^     Q[20]    ^ M64[ 4]) + (    XL64    ^ Q[28] ^ Q[ 4]);
    H[5] =                    (shl(XH64, 6) ^ shr(Q[21],6) ^ M64[ 5]) + (    XL64    ^ Q[29] ^ Q[ 5]);
    H[6] =                    (shr(XH64, 4) ^ shl(Q[22],6) ^ M64[ 6]) + (    XL64    ^ Q[30] ^ Q[ 6]);
    H[7] =                    (shr(XH64,11) ^ shl(Q[23],2) ^ M64[ 7]) + (    XL64    ^ Q[31] ^ Q[ 7]);

    H[ 8] = rotl64(H[4], 9) + (    XH64     ^     Q[24]    ^ M64[ 8]) + (shl(XL64,8) ^ Q[23] ^ Q[ 8]);
    H[ 9] = rotl64(H[5],10) + (    XH64     ^     Q[25]    ^ M64[ 9]) + (shr(XL64,6) ^ Q[16] ^ Q[ 9]);
    H[10] = rotl64(H[6],11) + (    XH64     ^     Q[26]    ^ M64[10]) + (shl(XL64,6) ^ Q[17] ^ Q[10]);
    H[11] = rotl64(H[7],12) + (    XH64     ^     Q[27]    ^ M64[11]) + (shl(XL64,4) ^ Q[18] ^ Q[11]);
    H[12] = rotl64(H[0],13) + (    XH64     ^     Q[28]    ^ M64[12]) + (shr(XL64,3) ^ Q[19] ^ Q[12]);
    H[13] = rotl64(H[1],14) + (    XH64     ^     Q[29]    ^ M64[13]) + (shr(XL64,4) ^ Q[20] ^ Q[13]);
    H[14] = rotl64(H[2],15) + (    XH64     ^     Q[30]    ^ M64[14]) + (shr(XL64,7) ^ Q[21] ^ Q[14]);
    H[15] = rotl64(H[3],16) + (    XH64     ^     Q[31]    ^ M64[15]) + (shr(XL64,2) ^ Q[22] ^ Q[15]);
}

static inline int _bluemidnightwish_init(hash_state *hs, int hashbitlen)
{
    switch(hashbitlen){
	case 224:
	    hs->bluemidnightwish.hashbitlen = hashbitlen;
	    hs->bluemidnightwish.bits_processed = 0;
	    hs->bluemidnightwish.unprocessed_bits = 0;
	    memcpy(hashState224(hs)->DoublePipe, i224p2,  16 * sizeof(unsigned int));
	    return NBSCrypto_OK;
	case 256:
	    hs->bluemidnightwish.hashbitlen = hashbitlen;
	    hs->bluemidnightwish.bits_processed = 0;
	    hs->bluemidnightwish.unprocessed_bits = 0;
	    memcpy(hashState256(hs)->DoublePipe, i256p2,  16 * sizeof(unsigned int));
	    return NBSCrypto_OK;
	case 384:
	    hs->bluemidnightwish.hashbitlen = hashbitlen;
	    hs->bluemidnightwish.bits_processed = 0;
	    hs->bluemidnightwish.unprocessed_bits = 0;
	    memcpy(hashState384(hs)->DoublePipe, i384p2,  16 * sizeof(unsigned long long));
	    return NBSCrypto_OK;
	case 512:
	    hs->bluemidnightwish.hashbitlen = hashbitlen;
	    hs->bluemidnightwish.bits_processed = 0;
	    hs->bluemidnightwish.unprocessed_bits = 0;
	    memcpy(hashState512(hs)->DoublePipe, i512p2,  16 * sizeof(unsigned long long));
	    return NBSCrypto_OK;
	default: return NBSCrypto_ERROR;
    }
}




#pragma mark - FUNCTIONS
int bluemidnightwish_224_init(hash_state *hs){return _bluemidnightwish_init(hs, 224);}
int bluemidnightwish_256_init(hash_state *hs){return _bluemidnightwish_init(hs, 256);}
int bluemidnightwish_384_init(hash_state *hs){return _bluemidnightwish_init(hs, 384);}
int bluemidnightwish_512_init(hash_state *hs){return _bluemidnightwish_init(hs, 512);}

int bluemidnightwish_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    int LastBytes;
    unsigned int *M32, *H256;
    unsigned long long *M64, *H512;

    switch(hs->bluemidnightwish.hashbitlen){
	case 224:
	case 256:
	    if (hs->bluemidnightwish.unprocessed_bits > 0){
		if ( hs->bluemidnightwish.unprocessed_bits + inlen > (64 * 8)){
		    return NBSCrypto_ERROR;
		}else{
		    LastBytes = (int)inlen >> 3;
		    memcpy(hashState256(hs)->LastPart + (hs->bluemidnightwish.unprocessed_bits >> 3), in, LastBytes );
		    hs->bluemidnightwish.unprocessed_bits += (int)inlen;
		    inlen = hs->bluemidnightwish.unprocessed_bits;
		    M32 = (unsigned int *)hashState256(hs)->LastPart;
		}
	    }else{
		M32 = (unsigned int *)in;
	    }

	    H256 = hashState256(hs)->DoublePipe;
	    while(inlen >= (64 * 8)){
		inlen -= (64 * 8);
		hs->bluemidnightwish.bits_processed += (64 * 8);
		_compression256(M32, H256);
		M32 += 16;
	    }
	    hs->bluemidnightwish.unprocessed_bits = (int)inlen;
	    if (inlen > 0){
		LastBytes = ((~(((- (int)inlen)>>3) & 0x01ff)) + 1) & 0x01ff;
		memcpy(hashState256(hs)->LastPart, M32, LastBytes );
	    }
	    return NBSCrypto_OK;

	case 384:
	case 512:
	    if (hs->bluemidnightwish.unprocessed_bits > 0){
		if ( hs->bluemidnightwish.unprocessed_bits + inlen > (128 * 8)){
		    return NBSCrypto_ERROR;
		}else{
		    LastBytes = (int)inlen >> 3;
		    memcpy(hashState512(hs)->LastPart + (hs->bluemidnightwish.unprocessed_bits >> 3), in, LastBytes );
		    hs->bluemidnightwish.unprocessed_bits += (int)inlen;
		    inlen = hs->bluemidnightwish.unprocessed_bits;
		    M64 = (unsigned long long *)hashState512(hs)->LastPart;
		}
	    }else{
		M64 = (unsigned long long *)in;
	    }

	    H512 = hashState512(hs)->DoublePipe;
	    while(inlen >= (128 * 8)){
		inlen -= (128 * 8);
		hs->bluemidnightwish.bits_processed += (128 * 8);
		_compression512(M64, H512);
		M64 += 16;
	    }
	    hs->bluemidnightwish.unprocessed_bits = (int)inlen;
	    if (inlen > 0){
		LastBytes = ((~(((- (int)inlen)>>3) & 0x03ff)) + 1) & 0x03ff;
		memcpy(hashState512(hs)->LastPart, M64, LastBytes );
	    }
	    return NBSCrypto_OK;

	default: return NBSCrypto_ERROR;
    }
}

int bluemidnightwish_done(hash_state *hs, unsigned char *out)
{
    int LastByte, PadOnePosition;
    unsigned int *M32, *H256;
    unsigned long long *M64, *H512;
    unsigned long long databitlen;

    H256 = NULL;
    H512 = NULL;

    switch(hs->bluemidnightwish.hashbitlen){
	case 224:
	case 256:
	    LastByte = (int)hs->bluemidnightwish.unprocessed_bits >> 3;
	    PadOnePosition = 7 - (hs->bluemidnightwish.unprocessed_bits & 0x07);
	    hashState256(hs)->LastPart[LastByte] = (hashState256(hs)->LastPart[LastByte] & (0xff << (PadOnePosition + 1) )) \
	    ^ (0x01 << PadOnePosition);
	    M64 = (unsigned long long *)hashState256(hs)->LastPart;

	    if(hs->bluemidnightwish.unprocessed_bits < 448){
		memset( (hashState256(hs)->LastPart) + LastByte + 1, 0x00, 64 - LastByte - 9 );
		databitlen = (64 * 8);
		M64[7] = hs->bluemidnightwish.bits_processed + hs->bluemidnightwish.unprocessed_bits;
	    }else{
		memset( (hashState256(hs)->LastPart) + LastByte + 1, 0x00, (64 * 2) - LastByte - 9 );
		databitlen = (64 * 16);
		M64[15] = hs->bluemidnightwish.bits_processed + hs->bluemidnightwish.unprocessed_bits;
	    }

	    M32 = (unsigned int *)hashState256(hs)->LastPart;
	    H256 = hashState256(hs)->DoublePipe;
	    while(databitlen >= (64 * 8)){
		databitlen -= (64 * 8);
		_compression256(M32, H256);
		M32 += 16;
	    }
	    break;

	case 384:
	case 512:
	    LastByte = (int)hs->bluemidnightwish.unprocessed_bits >> 3;
	    PadOnePosition = 7 - (hs->bluemidnightwish.unprocessed_bits & 0x07);
	    hashState512(hs)->LastPart[LastByte] = (hashState512(hs)->LastPart[LastByte] & (0xff << (PadOnePosition + 1) )) \
	    ^ (0x01 << PadOnePosition);
	    M64 = (unsigned long long *)hashState512(hs)->LastPart;

	    if(hs->bluemidnightwish.unprocessed_bits < 960){
		memset( (hashState512(hs)->LastPart) + LastByte + 1, 0x00, 128 - LastByte - 9 );
		databitlen = (128 * 8);
		M64[15] = hs->bluemidnightwish.bits_processed + hs->bluemidnightwish.unprocessed_bits;
	    }else{
		memset( (hashState512(hs)->LastPart) + LastByte + 1, 0x00, (128 * 2) - LastByte - 9 );
		databitlen = (128 * 16);
		M64[31] = hs->bluemidnightwish.bits_processed + hs->bluemidnightwish.unprocessed_bits;
	    }

	    H512 = hashState512(hs)->DoublePipe;
	    while(databitlen >= (128 * 8)){
		databitlen -= (128 * 8);
		_compression512(M64, H512);
		M64 += 16;
	    }
	    break;

	default: return NBSCrypto_ERROR;
    }

    switch(hs->bluemidnightwish.hashbitlen){
	case 224:
	    memcpy(out, H256 +  9, 28);
	    return NBSCrypto_OK;
	case 256:
	    memcpy(out, H256 +  8, 32);
	    return NBSCrypto_OK;
	case 384:
	    memcpy(out, H512 + 10, 48);
	    return NBSCrypto_OK;
	case 512:
	    memcpy(out, H512 +  8, 64);
	    return NBSCrypto_OK;
	default: return NBSCrypto_ERROR;
    }
}
