//
//	chi.c
//	Authors / Developers		: Phil Hawkes, Cameron McDonald
//	Last Modified (Original)	: 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor chi_224_desc =
{
    "chi-224",
    18,
    28,
    64,
    &chi_224_init,
    &chi_process,
    &chi_done,
    NULL
};

const struct hash_descriptor chi_256_desc =
{
    "chi-256",
    19,
    32,
    64,
    &chi_256_init,
    &chi_process,
    &chi_done,
    NULL
};

const struct hash_descriptor chi_384_desc =
{
    "chi-384",
    18,
    48,
    64,
    &chi_384_init,
    &chi_process,
    &chi_done,
    NULL
};

const struct hash_descriptor chi_512_desc =
{
    "chi-512",
    18,
    64,
    64,
    &chi_512_init,
    &chi_process,
    &chi_done,
    NULL
};




#pragma mark - DEFINES

typedef enum {
    _256_MSG_BLK_LEN = 512,
    _512_MSG_BLK_LEN = 1024
} MsgBlkLen;

typedef enum {
    _224_HASH_BIT_LEN = 224,
    _256_HASH_BIT_LEN = 256,
    _384_HASH_BIT_LEN = 384,
    _512_HASH_BIT_LEN = 512
} HashBitLen;

#define _MIN(x, y) ((x) < (y) ? (x) : (y))
#define _256_MAP _map
#define _512_MAP _map
#define _256_MSG_N (_256_MSG_BLK_LEN / 64)
#define _512_MSG_N (_512_MSG_BLK_LEN / 64)

#define _BYTE(x, i) ((unsigned char)(((x) >> (8 * (7 - i))) & 0xFF))

#define _BYTE2WORD(b) (			\
(((unsigned long long)(b)[0] & 0xFF) << 56) |	\
(((unsigned long long)(b)[1] & 0xFF) << 48) |	\
(((unsigned long long)(b)[2] & 0xFF) << 40) |	\
(((unsigned long long)(b)[3] & 0xFF) << 32) |	\
(((unsigned long long)(b)[4] & 0xFF) << 24) |	\
(((unsigned long long)(b)[5] & 0xFF) << 16) |	\
(((unsigned long long)(b)[6] & 0xFF) <<  8) |	\
(((unsigned long long)(b)[7] & 0xFF))		\
)

#define _WORD2BYTE(w, b)	\
do {			\
(b)[7] = _BYTE(w, 7);	\
(b)[6] = _BYTE(w, 6);	\
(b)[5] = _BYTE(w, 5);	\
(b)[4] = _BYTE(w, 4);	\
(b)[3] = _BYTE(w, 3);	\
(b)[2] = _BYTE(w, 2);	\
(b)[1] = _BYTE(w, 1);	\
(b)[0] = _BYTE(w, 0);	\
} while(0)

const unsigned long long K[] = {
    0x9B05688C2B3E6C1FULL, 0xDBD99E6FF3C90BDCULL, 0x4DBC64712A5BB168ULL, 0x767E27C3CF76C8E7ULL,
    0x21EE9AC5EF4C823AULL, 0xB36CCFC1204A9BD8ULL, 0x754C8A7FB36BD941ULL, 0xCF20868F04A825E9ULL,
    0xABB379E0A8838BB0ULL, 0x12D8B70A5959E391ULL, 0xB59168FA9F69E181ULL, 0x15C7D4918739F18FULL,
    0x4B547673EA8D68E0ULL, 0x3CED7326FCD0EF81ULL, 0x09F1D77309998460ULL, 0x1AF3937415E91F32ULL,
    0x1F83D9ABFB41BD6BULL, 0x23C4654C2A217583ULL, 0x2842012131573F2AULL, 0xA59916ACA3991FCAULL,
    0xEC1B7C06FD19D256ULL, 0x1EC785BCDC8BAF26ULL, 0x69CA4E0FF2E6BDD8ULL, 0xCA2575EE6C950D0EULL,
    0x5BCF66D2FB3D99F6ULL, 0x9D6D08C7BBCA18F3ULL, 0xEEF64039F2175E83ULL, 0x00ED5AEBAA2AB6E0ULL,
    0x5040712FC29AD308ULL, 0x6DAFE433438D2C43ULL, 0xBD7FAA3F06C71F15ULL, 0x03B5AA8CE9B6A4DDULL,
    0x5BE0CD19137E2179ULL, 0x867F5E3B72221265ULL, 0x43B6CBE0D67F4A20ULL, 0xDB99D767CB0E4933ULL,
    0xDC450DBC469248BDULL, 0xFE1E5E4876100D6FULL, 0xB799D29EA1733137ULL, 0x16EA7ABCF92053C4ULL,
    0xBE3ECE968DBA92ACULL, 0x18538F84D82C318BULL, 0x38D79F4E9C8A18C0ULL, 0xA8BBC28F1271F1F7ULL,
    0x2796E71067D2C8CCULL, 0xDE1BF2334EDB3FF6ULL, 0xB094D782A857F9C1ULL, 0x639B484B0C1DAED1ULL,
    0xCBBB9D5DC1059ED8ULL, 0xE7730EAFF25E24A3ULL, 0xF367F2FC266A0373ULL, 0xFE7A4D34486D08AEULL,
    0xD41670A136851F32ULL, 0x663914B66B4B3C23ULL, 0x1B9E3D7740A60887ULL, 0x63C11D86D446CB1CULL,
    0xD167D2469049D628ULL, 0xDDDBB606B9A49E38ULL, 0x557F1C8BEE68A7F7ULL, 0xF99DC58B50F924BDULL,
    0x205ACC9F653512A5ULL, 0x67C66344E4BAB193ULL, 0x18026E467960D0C8ULL, 0xA2F5D84DAECA8980ULL,
    0x629A292A367CD507ULL, 0x98E67012D90CBB6DULL, 0xEED758D1D18C7E35ULL, 0x031C02E4437DC71EULL,
    0x79B63D6482198EB7ULL, 0x936A9D7E8C9E4B33ULL, 0xB30CA682C3E6C65DULL, 0xCC442382BA4262FAULL,
    0x51179BA5A1D37FF6ULL, 0x7202BDE7A98EEA51ULL, 0x2B9F65D1DF9C610FULL, 0xF56B742B0AF1CE83ULL,
    0xF9989D199B75848BULL, 0xD142F19D8B46D578ULL, 0x7A7580514D75EA33ULL, 0xB74F9690808E704DULL
};

const unsigned long long _224_init[] = {
    0xA54FF53A5F1D36F1ULL, 0xCEA7E61FC37A20D5ULL, 0x4A77FE7B78415DFCULL, 0x8E34A6FE8E2DF92AULL,
    0x4E5B408C9C97D4D8ULL, 0x24A05EEE29922401ULL
};

const unsigned long long _256_init[] = {
    0x510E527FADE682D1ULL, 0xDE49E330E42B4CBBULL, 0x29BA5A455316E0C6ULL, 0x5507CD18E9E51E69ULL,
    0x4F9B11C81009A030ULL, 0xE3D3775F155385C6ULL
};

const unsigned long long _384_init[] = {
    0xA54FF53A5F1D36F1ULL, 0xCEA7E61FC37A20D5ULL, 0x4A77FE7B78415DFCULL, 0x8E34A6FE8E2DF92AULL,
    0x4E5B408C9C97D4D8ULL, 0x24A05EEE29922401ULL, 0x5A8176CFFC7C2224ULL, 0xC3EDEBDA29BEC4C8ULL,
    0x8A074C0F4D999610ULL
};

const unsigned long long _512_init[] = {
    0x510E527FADE682D1ULL, 0xDE49E330E42B4CBBULL, 0x29BA5A455316E0C6ULL, 0x5507CD18E9E51E69ULL,
    0x4F9B11C81009A030ULL, 0xE3D3775F155385C6ULL, 0x489221632788FB30ULL, 0x41921DB8FEEB38C2ULL,
    0x9AF94A7C48BBD5B6ULL
};




#pragma mark - INLINE

static inline unsigned int _rotr32(unsigned int X, int r)
{
    return (X >> r) | (X << (32 - r));
}

static inline unsigned long long _rotr64(unsigned long long X, int r)
{
    return (X >> r) | (X << (64 - r));
}

static inline unsigned long long _drotr32(unsigned long long X, int r1, int r2)
{
    return (unsigned long long)_rotr32((unsigned int)(X >> 32), r1) << 32 | _rotr32((unsigned int)X, r2);
}

static inline unsigned long long _swap8(unsigned long long X)
{
    X = (X & 0xFFFFFFFF00000000ULL) >> 32 | (X & 0x00000000FFFFFFFFULL) << 32;
    X = (X & 0xFFFF0000FFFF0000ULL) >> 16 | (X & 0x0000FFFF0000FFFFULL) << 16;
    X = (X & 0xFF00FF00FF00FF00ULL) >>  8 | (X & 0x00FF00FF00FF00FFULL) <<  8;

    return X;
}

static inline unsigned long long _swap32(unsigned long long X)
{
    return _rotr64(X, 32);
}

static inline unsigned long long _256_theta0(unsigned long long X)
{
    return _drotr32(X, 21, 21) ^ _drotr32(X, 26, 26) ^ _drotr32(X, 30, 30);
}

static inline unsigned long long _512_theta0(unsigned long long X)
{
    return _rotr64(X,  5) ^ _rotr64(X,  6) ^ _rotr64(X, 43);
}

static inline unsigned long long _256_theta1(unsigned long long X)
{
    return _drotr32(X, 14, 14) ^ _drotr32(X, 24, 24) ^ _drotr32(X, 31, 31);
}

static inline unsigned long long _512_theta1(unsigned long long X)
{
    return _rotr64(X, 20) ^ _rotr64(X, 30) ^ _rotr64(X, 49);
}

static inline unsigned long long _256_mu0(unsigned long long X)
{
    return _rotr64(X, 36) ^ _rotr64(X, 18) ^ (X >> 1);
}

static inline unsigned long long _512_mu0(unsigned long long X)
{
    return _rotr64(X, 36) ^ _rotr64(X, 18) ^ (X >> 1);
}

static inline unsigned long long _256_mu1(unsigned long long X)
{
    return _rotr64(X, 59) ^ _rotr64(X, 37) ^ (X >> 10);
}

static inline unsigned long long _512_mu1(unsigned long long X)
{
    return _rotr64(X, 60) ^ _rotr64(X, 30) ^ (X >> 3);
}

static inline unsigned long long _map0(unsigned long long R, unsigned long long S, unsigned long long T, unsigned long long U)
{
    return    ( R & ~S &  T &  U)
    | (     ~S & ~T & ~U)
    | (~R      & ~T &  U)
    | (~R &  S &  T     )
    | ( R      & ~T & ~U);
}

static inline unsigned long long _map1(unsigned long long R, unsigned long long S, unsigned long long T, unsigned long long U)
{
    return    ( R &  S &  T & ~U)
    | ( R & ~S & ~T & ~U)
    | (~R & ~S &  T     )
    | (      S & ~T &  U)
    | (~R           &  U);
}

static inline unsigned long long _map2(unsigned long long R, unsigned long long S, unsigned long long T, unsigned long long U)
{
    return    (~R & ~S &  T &  U)
    | (~R &  S &  T & ~U)
    | (      S & ~T &  U)
    | ( R      & ~T & ~U)
    | ( R &  S      &  U)
    | ( R & ~S      & ~U);
}

static inline void _map(unsigned long long R, unsigned long long S, unsigned long long T, unsigned long long U, unsigned long long *X, unsigned long long *Y, unsigned long long *Z, int i)
{
    unsigned long long M[3];

    M[0] = _map0(R, S, T, U);
    M[1] = _map1(R, S, T, U);
    M[2] = _map2(R, S, T, U);

    *X = M[(i + 0) % 3];
    *Y = M[(i + 1) % 3];
    *Z = M[(i + 2) % 3];
}

static inline void _256_datainput(unsigned long long preR, unsigned long long preS, unsigned long long preT, unsigned long long preU, unsigned long long V0, unsigned long long V1, unsigned long long *R, unsigned long long *S, unsigned long long *T, unsigned long long *U)
{
    *R = preR ^ V0;
    *S = preS ^ V1;
    *T = preT ^ _256_theta0(V0);
    *U = preU ^ _256_theta1(V1);
}

static inline void _512_datainput(unsigned long long preR, unsigned long long preS, unsigned long long preT, unsigned long long preU, unsigned long long V0, unsigned long long V1, unsigned long long *R, unsigned long long *S, unsigned long long *T, unsigned long long *U)
{
    *R = preR ^ V0;
    *S = preS ^ V1;
    *T = preT ^ _512_theta0(V0);
    *U = preU ^ _512_theta1(V1);
}

static inline void _256_premix(unsigned long long A, unsigned long long B, unsigned long long D, unsigned long long E, unsigned long long *preR, unsigned long long *preS, unsigned long long *preT, unsigned long long *preU)
{
    *preR = _drotr32(B, 8, 8)		^ _drotr32(_swap32(D),  5,  1);
    *preS = A				^ _drotr32(_swap32(D), 18, 17);
    *preT = _drotr32(_swap32(A), 7, 26)	^ _drotr32(D, 14, 22);
    *preU = _drotr32(A, 17, 12)		^ _drotr32(_swap32(E),  2, 23);
}

static inline void _512_premix(unsigned long long A, unsigned long long B, unsigned long long D, unsigned long long E, unsigned long long G, unsigned long long P, unsigned long long *preR, unsigned long long *preS, unsigned long long *preT, unsigned long long *preU)
{
    *preR = _rotr64(B, 11)	^ _rotr64(D,  8) ^ _rotr64(G, 13);
    *preS = A			^ _rotr64(D, 21) ^ _rotr64(G, 29);
    *preT = _rotr64(A, 11)	^ _rotr64(D, 38) ^ P;
    *preU = _rotr64(A, 26)	^ _rotr64(E, 40) ^ _rotr64(G, 50);
}

static inline void _256_postmix(unsigned long long X, unsigned long long Y, unsigned long long Z, unsigned long long *XX, unsigned long long *YY, unsigned long long *ZZ, unsigned long long *AA, unsigned long long *DD)
{
    *XX = X;
    *YY = _swap8(_drotr32(Y, 5, 5));
    *ZZ = _swap32(Z);
    *AA = _rotr64(*XX + *YY, 16);
    *DD = _rotr64(*YY + *ZZ, 48);
}

static inline void _512_postmix(unsigned long long X, unsigned long long Y, unsigned long long Z, unsigned long long *XX, unsigned long long *YY, unsigned long long *ZZ, unsigned long long *AA, unsigned long long *DD, unsigned long long *GG)
{
    unsigned long long temp;

    *XX = X;
    *YY = _swap8(_rotr64(Y, 31));
    *ZZ = _swap32(Z);

    temp = *XX + *YY;
    *AA = _rotr64(temp, 16);

    temp = *YY + *ZZ;
    *DD = _rotr64(temp, 48);

    temp = *ZZ + (*XX << 1);
    *GG = temp;
}

static inline void _256_message_expansion(unsigned long long *W)
{
    int i;
    for (i = 8; i < 2 * 20; ++i){
	W[i] = W[i - 8] ^ _256_mu0(W[i - 7]) ^ _256_mu1(W[i - 2]);
    }
}

static inline void _512_message_expansion(unsigned long long *W)
{
    int i;
    for (i = 16; i < 2 * 40; ++i){
	W[i] = W[i - 16]
	^ W[i -  7]
	^ _512_mu0(W[i - 15])
	^ _512_mu1(W[i - 2]);
    }
}

static inline void _256_update(hash_state *hs, int final)
{
    int i;

    unsigned long long W[2*20];
    unsigned long long A, B, C, D, E, F;
    unsigned long long preR, preS, preT, preU;
    unsigned long long V0, V1;
    unsigned long long R, S, T, U;
    unsigned long long X, Y, Z, XX, YY, ZZ;
    unsigned long long AA, DD, newA, newD;

    A = hs->chi.hs_State.small[0];
    B = hs->chi.hs_State.small[1];
    C = hs->chi.hs_State.small[2];
    D = hs->chi.hs_State.small[3];
    E = hs->chi.hs_State.small[4];
    F = hs->chi.hs_State.small[5];

    if (final){
	A = _rotr64(A, 1);
	B = _rotr64(B, 1);
	C = _rotr64(C, 1);
	D = _rotr64(D, 1);
	E = _rotr64(E, 1);
	F = _rotr64(F, 1);
    }

    for (i = 0; i < _256_MSG_N; ++i){
	W[i] = _BYTE2WORD(hs->chi.hs_DataBuffer + 8 * i);
    }
    _256_message_expansion(W);

    for (i = 0; i < 20; ++i){
	_256_premix(A, B, D, E, &preR, &preS, &preT, &preU);
	V0 = W[2*i  ] ^ K[2*i  ];
	V1 = W[2*i+1] ^ K[2*i+1];
	_256_datainput(preR, preS, preT, preU, V0, V1, &R, &S, &T, &U);
	_256_MAP(R, S, T, U, &X, &Y, &Z, i);
	_256_postmix(X, Y, Z, &XX, &YY, &ZZ, &AA, &DD);

	newA = AA ^ F;
	newD = DD ^ C;

	F = E; E = D; D = newD;
	C = B; B = A; A = newA;
    }

    hs->chi.hs_State.small[0] = _rotr64(hs->chi.hs_State.small[0], 1) ^ A;
    hs->chi.hs_State.small[1] = _rotr64(hs->chi.hs_State.small[1], 1) ^ B;
    hs->chi.hs_State.small[2] = _rotr64(hs->chi.hs_State.small[2], 1) ^ C;
    hs->chi.hs_State.small[3] = _rotr64(hs->chi.hs_State.small[3], 1) ^ D;
    hs->chi.hs_State.small[4] = _rotr64(hs->chi.hs_State.small[4], 1) ^ E;
    hs->chi.hs_State.small[5] = _rotr64(hs->chi.hs_State.small[5], 1) ^ F;
}

static inline void _512_update(hash_state *hs, int final)
{
    int i;

    unsigned long long W[2*40];
    unsigned long long A, B, C, D, E, F, G, P, Q;
    unsigned long long preR, preS, preT, preU;
    unsigned long long V0, V1;
    unsigned long long R, S, T, U;
    unsigned long long X, Y, Z, XX, YY, ZZ;
    unsigned long long AA, DD, GG, newA, newD, newG;

    A = hs->chi.hs_State.large[0];
    B = hs->chi.hs_State.large[1];
    C = hs->chi.hs_State.large[2];
    D = hs->chi.hs_State.large[3];
    E = hs->chi.hs_State.large[4];
    F = hs->chi.hs_State.large[5];
    G = hs->chi.hs_State.large[6];
    P = hs->chi.hs_State.large[7];
    Q = hs->chi.hs_State.large[8];

    if (final){
	A = _rotr64(A, 1);
	B = _rotr64(B, 1);
	C = _rotr64(C, 1);
	D = _rotr64(D, 1);
	E = _rotr64(E, 1);
	F = _rotr64(F, 1);
	G = _rotr64(G, 1);
	P = _rotr64(P, 1);
	Q = _rotr64(Q, 1);
    }

    for (i = 0; i < _512_MSG_N; ++i){
	W[i] = _BYTE2WORD(hs->chi.hs_DataBuffer + 8*i);
    }
    _512_message_expansion(W);

    for (i = 0; i < 40; ++i){
	_512_premix(A, B, D, E, G, P, &preR, &preS, &preT, &preU);
	V0 = W[2*i  ] ^ K[2*i  ];
	V1 = W[2*i+1] ^ K[2*i+1];
	_512_datainput(preR, preS, preT, preU, V0, V1, &R, &S, &T, &U);
	_512_MAP(R, S, T, U, &X, &Y, &Z, i);
	_512_postmix(X, Y, Z, &XX, &YY, &ZZ, &AA, &DD, &GG);

	newA = AA ^ Q;
	newD = DD ^ C;
	newG = GG ^ F;

	Q = P; P = G; G = newG;
	F = E; E = D; D = newD;
	C = B; B = A; A = newA;
    }

    hs->chi.hs_State.large[0] = _rotr64(hs->chi.hs_State.large[0], 1) ^ A;
    hs->chi.hs_State.large[1] = _rotr64(hs->chi.hs_State.large[1], 1) ^ B;
    hs->chi.hs_State.large[2] = _rotr64(hs->chi.hs_State.large[2], 1) ^ C;
    hs->chi.hs_State.large[3] = _rotr64(hs->chi.hs_State.large[3], 1) ^ D;
    hs->chi.hs_State.large[4] = _rotr64(hs->chi.hs_State.large[4], 1) ^ E;
    hs->chi.hs_State.large[5] = _rotr64(hs->chi.hs_State.large[5], 1) ^ F;
    hs->chi.hs_State.large[6] = _rotr64(hs->chi.hs_State.large[6], 1) ^ G;
    hs->chi.hs_State.large[7] = _rotr64(hs->chi.hs_State.large[7], 1) ^ P;
    hs->chi.hs_State.large[8] = _rotr64(hs->chi.hs_State.large[8], 1) ^ Q;
}

static inline int _inc_total_len(hash_state *hs)
{
    unsigned long long old_len;

    old_len = hs->chi.hs_TotalLenLow;
    hs->chi.hs_TotalLenLow += hs->chi.hs_DataLen;
    if (old_len > hs->chi.hs_TotalLenLow)
    {
	switch (hs->chi.hs_HashBitLen)
	{
	    case 224:
	    case 256:
		return NBSCrypto_ERROR;

	    case 384:
	    case 512:
		if (++hs->chi.hs_TotalLenHigh == 0)
		    return NBSCrypto_ERROR;
	}
    }

    return NBSCrypto_OK;
}

static inline void _hash(hash_state *hs, int final)
{
    switch (hs->chi.hs_HashBitLen)
    {
	case 224:
	case 256:
	    _256_update(hs, final);
	    break;

	case 384:
	case 512:
	    _512_update(hs, final);
	    break;
    }
}

static inline int _chi_init(hash_state *hs, int hashbitlen)
{
    if (hs == NULL){
	return NBSCrypto_ERROR;
    }

    switch (hashbitlen){
	default:{
	    return NBSCrypto_ERROR;
	}
	case 224:{
	    memcpy(hs->chi.hs_State.small, _224_init, 6 * sizeof(unsigned long long));
	    hs->chi.hs_MessageLen = _256_MSG_BLK_LEN;
	    break;
	}
	case 256:{
	    memcpy(hs->chi.hs_State.small, _256_init, 6 * sizeof(unsigned long long));
	    hs->chi.hs_MessageLen = _256_MSG_BLK_LEN;
	    break;
	}
	case 384:{
	    memcpy(hs->chi.hs_State.large, _384_init, 9 * sizeof(unsigned long long));
	    hs->chi.hs_MessageLen = _512_MSG_BLK_LEN;
	    break;
	}
	case 512:{
	    memcpy(hs->chi.hs_State.large, _512_init, 9 * sizeof(unsigned long long));
	    hs->chi.hs_MessageLen = _512_MSG_BLK_LEN;
	    break;
	}
    }

    hs->chi.hs_HashBitLen = (HashBitLen)hashbitlen;
    hs->chi.hs_DataLen      = 0;
    hs->chi.hs_TotalLenLow  = 0;
    hs->chi.hs_TotalLenHigh = 0;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS

int chi_224_init(hash_state *hs){return _chi_init(hs, 224);}
int chi_256_init(hash_state *hs){return _chi_init(hs, 256);}
int chi_384_init(hash_state *hs){return _chi_init(hs, 384);}
int chi_512_init(hash_state *hs){return _chi_init(hs, 512);}

int chi_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    int ret;
    unsigned int cs;

    if (hs == NULL){
	return NBSCrypto_ERROR;
    }
    if (in == NULL){
	return NBSCrypto_ERROR;
    }
    if ((hs->chi.hs_DataLen & 0x7) != 0){
	return NBSCrypto_ERROR;
    }

    while (inlen > 0){
	cs = _MIN((unsigned int)inlen, hs->chi.hs_MessageLen - hs->chi.hs_DataLen);

	memcpy(hs->chi.hs_DataBuffer+hs->chi.hs_DataLen / 8, in, (cs + 7) / 8);
	in += cs / 8;
	inlen -= cs;
	hs->chi.hs_DataLen += cs;

	if (hs->chi.hs_DataLen >= (unsigned int)hs->chi.hs_MessageLen){
	    _hash(hs, 0);
	    ret = _inc_total_len(hs);
	    if (ret != NBSCrypto_OK){
		return ret;
	    }
	    hs->chi.hs_DataLen = 0;
	}
    }

    return NBSCrypto_OK;
}

int chi_done(hash_state *hs, unsigned char *out)
{
    int ret;
    unsigned int whole_bytes;
    unsigned int last_byte_bits;
    unsigned int left_over_bytes;
    unsigned int length_bytes = 0;

    if (hs == NULL){
	return NBSCrypto_ERROR;
    }
    if (out == NULL){
	return NBSCrypto_ERROR;
    }

    ret = _inc_total_len(hs);
    if (ret != NBSCrypto_OK){
	return ret;
    }

    switch (hs->chi.hs_HashBitLen)
    {
	case 224:
	case 256:
	    length_bytes = sizeof(unsigned long long);
	    break;
	case 384:
	case 512:
	    length_bytes = sizeof(unsigned long long) * 2;
	    break;
    }

    whole_bytes = hs->chi.hs_DataLen / 8;
    last_byte_bits = hs->chi.hs_DataLen % 8;

    hs->chi.hs_DataBuffer[whole_bytes] &= ~((1 << (7-last_byte_bits)) - 1);
    hs->chi.hs_DataBuffer[whole_bytes] |= (1 << (7-last_byte_bits));

    hs->chi.hs_DataLen += (8 - last_byte_bits);

    left_over_bytes = (hs->chi.hs_MessageLen - hs->chi.hs_DataLen) / 8;

    if (left_over_bytes < length_bytes){
	memset(hs->chi.hs_DataBuffer + hs->chi.hs_DataLen/8, 0, left_over_bytes);
	_hash(hs, 0);
	hs->chi.hs_DataLen = 0;
	left_over_bytes = hs->chi.hs_MessageLen / 8;
    }

    memset(hs->chi.hs_DataBuffer + hs->chi.hs_DataLen / 8, 0, left_over_bytes);

    whole_bytes = hs->chi.hs_MessageLen / 8 - length_bytes;
    if (length_bytes == sizeof(unsigned long long) * 2){
	_WORD2BYTE(hs->chi.hs_TotalLenHigh, hs->chi.hs_DataBuffer + whole_bytes);
	whole_bytes += sizeof(unsigned long long);
    }else{
	if (hs->chi.hs_TotalLenHigh != 0)
	    return NBSCrypto_ERROR;
    }

    _WORD2BYTE(hs->chi.hs_TotalLenLow, hs->chi.hs_DataBuffer + whole_bytes);
    hs->chi.hs_DataLen = hs->chi.hs_MessageLen;

    _hash(hs, 1);
    hs->chi.hs_DataLen = 0;

    switch(hs->chi.hs_HashBitLen)
    {
	case 224:
	    _WORD2BYTE(hs->chi.hs_State.large[0],out);
	    _WORD2BYTE(hs->chi.hs_State.large[1],out +  8);
	    _WORD2BYTE(hs->chi.hs_State.large[3],out + 16);
	    out[24] = _BYTE(hs->chi.hs_State.large[4], 0);
	    out[25] = _BYTE(hs->chi.hs_State.large[4], 1);
	    out[26] = _BYTE(hs->chi.hs_State.large[4], 2);
	    out[27] = _BYTE(hs->chi.hs_State.large[4], 3);
	    break;

	case 256:
	    _WORD2BYTE(hs->chi.hs_State.large[0],out);
	    _WORD2BYTE(hs->chi.hs_State.large[1],out +  8);
	    _WORD2BYTE(hs->chi.hs_State.large[3],out + 16);
	    _WORD2BYTE(hs->chi.hs_State.large[4],out + 24);
	    break;

	case 384:
	    _WORD2BYTE(hs->chi.hs_State.large[0],out);
	    _WORD2BYTE(hs->chi.hs_State.large[1],out +  8);
	    _WORD2BYTE(hs->chi.hs_State.large[2],out + 16);
	    _WORD2BYTE(hs->chi.hs_State.large[3],out + 24);
	    _WORD2BYTE(hs->chi.hs_State.large[4],out + 32);
	    _WORD2BYTE(hs->chi.hs_State.large[5],out + 40);
	    break;

	case 512:
	    _WORD2BYTE(hs->chi.hs_State.large[0],out);
	    _WORD2BYTE(hs->chi.hs_State.large[1],out +  8);
	    _WORD2BYTE(hs->chi.hs_State.large[2],out + 16);
	    _WORD2BYTE(hs->chi.hs_State.large[3],out + 24);
	    _WORD2BYTE(hs->chi.hs_State.large[4],out + 32);
	    _WORD2BYTE(hs->chi.hs_State.large[5],out + 40);
	    _WORD2BYTE(hs->chi.hs_State.large[6],out + 48);
	    _WORD2BYTE(hs->chi.hs_State.large[7],out + 56);
	    break;
    }

    return NBSCrypto_OK;
}
