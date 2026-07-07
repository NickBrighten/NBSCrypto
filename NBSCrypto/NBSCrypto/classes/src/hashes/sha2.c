//
//	sha2.c
//	Authors / Developers		: National Institute of Standards and Technology, National Security Agency
//	Last Modified (Original)	: 2012 (2004)
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor sha224_desc =
{
    "sha224",
    10370244,
    28,
    64,
    &sha224_init,
    &sha256_process,
    &sha224_done,
    NULL
};

const struct hash_descriptor sha256_desc =
{
    "sha256",
    10370256,
    32,
    64,
    &sha256_init,
    &sha256_process,
    &sha256_done,
    NULL
};

const struct hash_descriptor sha384_desc =
{
    "sha384",
    10370384,
    48,
    128,
    &sha384_init,
    &sha512_process,
    &sha384_done,
    NULL
};

const struct hash_descriptor sha512_desc =
{
    "sha512",
    10370512,
    64,
    128,
    &sha512_init,
    &sha512_process,
    &sha512_done,
    NULL
};

const struct hash_descriptor sha512_224_desc =
{
    "sha512-224",
    10375244,
    28,
    128,
    &sha512_224_init,
    &sha512_process,
    &sha512_224_done,
    NULL
};

const struct hash_descriptor sha512_256_desc =
{
    "sha512-256",
    10375256,
    32,
    128,
    &sha512_256_init,
    &sha512_process,
    &sha512_256_done,
    NULL
};




#pragma mark - DEFINES
#define Ch(x,y,z)	(z ^ (x & (y ^ z)))
#define Maj(x,y,z)	(((x | y) & z) | (x & y))
#define S64(x, n)	RORc((x),(n))
#define S128(x, n)      ROR64c(x, n)
#define R64(x, n)	(((x)&0xFFFFFFFFUL)>>(n))
#define R128(x, n)      (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((unsigned long long)n))
#define Sigma64_0(x)	(S64(x, 2) ^ S64(x, 13) ^ S64(x, 22))
#define Sigma64_1(x)	(S64(x, 6) ^ S64(x, 11) ^ S64(x, 25))
#define Sigma128_0(x)   (S128(x, 28) ^ S128(x, 34) ^ S128(x, 39))
#define Sigma128_1(x)   (S128(x, 14) ^ S128(x, 18) ^ S128(x, 41))
#define Gamma64_0(x)	(S64(x, 7) ^ S64(x, 18) ^ R64(x,  3))
#define Gamma64_1(x)	(S64(x,17) ^ S64(x, 19) ^ R64(x, 10))
#define Gamma128_0(x)   (S128(x,  1) ^ S128(x,  8) ^ R128(x,  7))
#define Gamma128_1(x)   (S128(x, 19) ^ S128(x, 61) ^ R128(x,  6))

#define STORE32H(x, y)										\
    do {(y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);	\
	(y)[2] = (unsigned char)(((x)>> 8)&255); (y)[3] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD32H(x, y)										\
    do {x = ((unsigned)((y)[0] & 255)<<24) | ((unsigned)((y)[1] & 255)<<16) |			\
	    ((unsigned)((y)[2] & 255)<< 8) | ((unsigned)((y)[3] & 255));			\
} while(0)

#define STORE64H(x, y)										\
    do {(y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);	\
	(y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);	\
	(y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);	\
	(y)[6] = (unsigned char)(((x)>> 8)&255); (y)[7] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD64H(x, y)					\
    do {x = (((unsigned long long)((y)[0] & 255))<<56)|	\
	    (((unsigned long long)((y)[1] & 255))<<48)|	\
	    (((unsigned long long)((y)[2] & 255))<<40)|	\
	    (((unsigned long long)((y)[3] & 255))<<32)|	\
	    (((unsigned long long)((y)[4] & 255))<<24)|	\
	    (((unsigned long long)((y)[5] & 255))<<16)|	\
	    (((unsigned long long)((y)[6] & 255))<< 8)|	\
	    (((unsigned long long)((y)[7] & 255)));	\
} while(0)

#define RORc(x, y) (((((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((y)&31)) | ((unsigned)(x)<<(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)
#define ROR64c(x, y) (((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((unsigned long long)(y)&CONST64(63))) | ((x)<<(((unsigned long long)64-((y)&63))&63))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define MIN(x, y) (((x)<(y))?(x):(y))

#define CONST64(n) n ## ULL


static const unsigned long long K[80] = {
    CONST64(0x428a2f98d728ae22), CONST64(0x7137449123ef65cd),
    CONST64(0xb5c0fbcfec4d3b2f), CONST64(0xe9b5dba58189dbbc),
    CONST64(0x3956c25bf348b538), CONST64(0x59f111f1b605d019),
    CONST64(0x923f82a4af194f9b), CONST64(0xab1c5ed5da6d8118),
    CONST64(0xd807aa98a3030242), CONST64(0x12835b0145706fbe),
    CONST64(0x243185be4ee4b28c), CONST64(0x550c7dc3d5ffb4e2),
    CONST64(0x72be5d74f27b896f), CONST64(0x80deb1fe3b1696b1),
    CONST64(0x9bdc06a725c71235), CONST64(0xc19bf174cf692694),
    CONST64(0xe49b69c19ef14ad2), CONST64(0xefbe4786384f25e3),
    CONST64(0x0fc19dc68b8cd5b5), CONST64(0x240ca1cc77ac9c65),
    CONST64(0x2de92c6f592b0275), CONST64(0x4a7484aa6ea6e483),
    CONST64(0x5cb0a9dcbd41fbd4), CONST64(0x76f988da831153b5),
    CONST64(0x983e5152ee66dfab), CONST64(0xa831c66d2db43210),
    CONST64(0xb00327c898fb213f), CONST64(0xbf597fc7beef0ee4),
    CONST64(0xc6e00bf33da88fc2), CONST64(0xd5a79147930aa725),
    CONST64(0x06ca6351e003826f), CONST64(0x142929670a0e6e70),
    CONST64(0x27b70a8546d22ffc), CONST64(0x2e1b21385c26c926),
    CONST64(0x4d2c6dfc5ac42aed), CONST64(0x53380d139d95b3df),
    CONST64(0x650a73548baf63de), CONST64(0x766a0abb3c77b2a8),
    CONST64(0x81c2c92e47edaee6), CONST64(0x92722c851482353b),
    CONST64(0xa2bfe8a14cf10364), CONST64(0xa81a664bbc423001),
    CONST64(0xc24b8b70d0f89791), CONST64(0xc76c51a30654be30),
    CONST64(0xd192e819d6ef5218), CONST64(0xd69906245565a910),
    CONST64(0xf40e35855771202a), CONST64(0x106aa07032bbd1b8),
    CONST64(0x19a4c116b8d2d0c8), CONST64(0x1e376c085141ab53),
    CONST64(0x2748774cdf8eeb99), CONST64(0x34b0bcb5e19b48a8),
    CONST64(0x391c0cb3c5c95a63), CONST64(0x4ed8aa4ae3418acb),
    CONST64(0x5b9cca4f7763e373), CONST64(0x682e6ff3d6b2b8a3),
    CONST64(0x748f82ee5defb2fc), CONST64(0x78a5636f43172f60),
    CONST64(0x84c87814a1f0ab72), CONST64(0x8cc702081a6439ec),
    CONST64(0x90befffa23631e28), CONST64(0xa4506cebde82bde9),
    CONST64(0xbef9a3f7b2c67915), CONST64(0xc67178f2e372532b),
    CONST64(0xca273eceea26619c), CONST64(0xd186b8c721c0c207),
    CONST64(0xeada7dd6cde0eb1e), CONST64(0xf57d4f7fee6ed178),
    CONST64(0x06f067aa72176fba), CONST64(0x0a637dc5a2c898a6),
    CONST64(0x113f9804bef90dae), CONST64(0x1b710b35131c471b),
    CONST64(0x28db77f523047d84), CONST64(0x32caab7b40c72493),
    CONST64(0x3c9ebe0a15c9bebc), CONST64(0x431d67c49c100d4c),
    CONST64(0x4cc5d4becb3e42b6), CONST64(0x597f299cfc657e2a),
    CONST64(0x5fcb6fab3ad6faec), CONST64(0x6c44198c4a475817)
};




#pragma mark - INLINE
static inline int _sha256_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned S[8], W[64], t0, t1;
    int i;

    for (i = 0; i < 8; i++) {
	S[i] = hs->sha256.state[i];
    }

    for (i = 0; i < 16; i++) {
	LOAD32H(W[i], buf + (4*i));
    }

    for (i = 16; i < 64; i++) {
	W[i] = Gamma64_1(W[i - 2]) + W[i - 7] + Gamma64_0(W[i - 15]) + W[i - 16];
    }

#define RND(a,b,c,d,e,f,g,h,i,ki)			\
    t0 = h + Sigma64_1(e) + Ch(e, f, g) + ki + W[i];	\
    t1 = Sigma64_0(a) + Maj(a, b, c);			\
    d += t0;						\
    h  = t0 + t1;

    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7], 0,0x428a2f98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6], 1,0x71374491);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5], 2,0xb5c0fbcf);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4], 3,0xe9b5dba5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3], 4,0x3956c25b);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2], 5,0x59f111f1);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1], 6,0x923f82a4);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0], 7,0xab1c5ed5);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7], 8,0xd807aa98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6], 9,0x12835b01);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);

#undef RND

    for (i = 0; i < 8; i++) {
	hs->sha256.state[i] = hs->sha256.state[i] + S[i];
    }
    return NBSCrypto_OK;
}

static inline int _sha512_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned long long S[8], W[80], t0, t1;
    int i;

    for (i = 0; i < 8; i++) {
	S[i] = hs->sha512.state[i];
    }

    for (i = 0; i < 16; i++) {
	LOAD64H(W[i], buf + (8*i));
    }

    for (i = 16; i < 80; i++) {
	W[i] = Gamma128_1(W[i - 2]) + W[i - 7] + Gamma128_0(W[i - 15]) + W[i - 16];
    }

#define RND(a,b,c,d,e,f,g,h,i)				\
    t0 = h + Sigma128_1(e) + Ch(e, f, g) + K[i] + W[i];	\
    t1 = Sigma128_0(a) + Maj(a, b, c);			\
    d += t0;						\
    h  = t0 + t1;

    for (i = 0; i < 80; i += 8) {
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i+0);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],i+1);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],i+2);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],i+3);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],i+4);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],i+5);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],i+6);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],i+7);
    }

#undef RND

    for (i = 0; i < 8; i++) {
	hs->sha512.state[i] = hs->sha512.state[i] + S[i];
    }

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int sha224_init(hash_state *hs)
{
    hs->sha256.curlen = 0;
    hs->sha256.length = 0;
    hs->sha256.state[0] = 0xc1059ed8UL;
    hs->sha256.state[1] = 0x367cd507UL;
    hs->sha256.state[2] = 0x3070dd17UL;
    hs->sha256.state[3] = 0xf70e5939UL;
    hs->sha256.state[4] = 0xffc00b31UL;
    hs->sha256.state[5] = 0x68581511UL;
    hs->sha256.state[6] = 0x64f98fa7UL;
    hs->sha256.state[7] = 0xbefa4fa4UL;
    return NBSCrypto_OK;
}

int sha256_init(hash_state *hs)
{
    hs->sha256.curlen = 0;
    hs->sha256.length = 0;
    hs->sha256.state[0] = 0x6A09E667UL;
    hs->sha256.state[1] = 0xBB67AE85UL;
    hs->sha256.state[2] = 0x3C6EF372UL;
    hs->sha256.state[3] = 0xA54FF53AUL;
    hs->sha256.state[4] = 0x510E527FUL;
    hs->sha256.state[5] = 0x9B05688CUL;
    hs->sha256.state[6] = 0x1F83D9ABUL;
    hs->sha256.state[7] = 0x5BE0CD19UL;
    return NBSCrypto_OK;
}

int sha384_init(hash_state *hs)
{
    hs->sha512.curlen = 0;
    hs->sha512.length = 0;
    hs->sha512.state[0] = CONST64(0xcbbb9d5dc1059ed8);
    hs->sha512.state[1] = CONST64(0x629a292a367cd507);
    hs->sha512.state[2] = CONST64(0x9159015a3070dd17);
    hs->sha512.state[3] = CONST64(0x152fecd8f70e5939);
    hs->sha512.state[4] = CONST64(0x67332667ffc00b31);
    hs->sha512.state[5] = CONST64(0x8eb44a8768581511);
    hs->sha512.state[6] = CONST64(0xdb0c2e0d64f98fa7);
    hs->sha512.state[7] = CONST64(0x47b5481dbefa4fa4);
    return NBSCrypto_OK;
}

int sha512_init(hash_state *hs)
{
    hs->sha512.curlen = 0;
    hs->sha512.length = 0;
    hs->sha512.state[0] = CONST64(0x6a09e667f3bcc908);
    hs->sha512.state[1] = CONST64(0xbb67ae8584caa73b);
    hs->sha512.state[2] = CONST64(0x3c6ef372fe94f82b);
    hs->sha512.state[3] = CONST64(0xa54ff53a5f1d36f1);
    hs->sha512.state[4] = CONST64(0x510e527fade682d1);
    hs->sha512.state[5] = CONST64(0x9b05688c2b3e6c1f);
    hs->sha512.state[6] = CONST64(0x1f83d9abfb41bd6b);
    hs->sha512.state[7] = CONST64(0x5be0cd19137e2179);
    return NBSCrypto_OK;
}

int sha512_224_init(hash_state *hs)
{
    hs->sha512.curlen = 0;
    hs->sha512.length = 0;
    hs->sha512.state[0] = CONST64(0x8C3D37C819544DA2);
    hs->sha512.state[1] = CONST64(0x73E1996689DCD4D6);
    hs->sha512.state[2] = CONST64(0x1DFAB7AE32FF9C82);
    hs->sha512.state[3] = CONST64(0x679DD514582F9FCF);
    hs->sha512.state[4] = CONST64(0x0F6D2B697BD44DA8);
    hs->sha512.state[5] = CONST64(0x77E36F7304C48942);
    hs->sha512.state[6] = CONST64(0x3F9D85A86A1D36C8);
    hs->sha512.state[7] = CONST64(0x1112E6AD91D692A1);
    return NBSCrypto_OK;
}

int sha512_256_init(hash_state *hs)
{
    hs->sha512.curlen = 0;
    hs->sha512.length = 0;
    hs->sha512.state[0] = CONST64(0x22312194FC2BF72C);
    hs->sha512.state[1] = CONST64(0x9F555FA3C84C64C2);
    hs->sha512.state[2] = CONST64(0x2393B86B6F53B151);
    hs->sha512.state[3] = CONST64(0x963877195940EABD);
    hs->sha512.state[4] = CONST64(0x96283EE2A88EFFE3);
    hs->sha512.state[5] = CONST64(0xBE5E1E2553863992);
    hs->sha512.state[6] = CONST64(0x2B0199FC2C85B8AA);
    hs->sha512.state[7] = CONST64(0x0EB72DDC81C52CA2);
    return NBSCrypto_OK;
}

int sha256_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;
    if (hs->sha256.curlen > sizeof(hs->sha256.buf)) {
	return NBSCrypto_ERROR;
    }
    if ((hs->sha256.length + inlen * 8) < hs->sha256.length) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	if (hs->sha256.curlen == 0 && inlen >= 64) {
	    if ((err = _sha256_compress(hs, in)) != NBSCrypto_OK) {
		return err;
	    }
	    hs->sha256.length += 64 * 8;
	    in		+= 64;
	    inlen	-= 64;
	} else {
	    n = MIN(inlen, (64 - hs->sha256.curlen));
	    memcpy(hs->sha256.buf + hs->sha256.curlen, in, (size_t)n);
	    hs->sha256.curlen += n;
	    in += n;
	    inlen -= n;
	    if (hs->sha256.curlen == 64) {
		if ((err = _sha256_compress(hs, hs->sha256.buf)) != NBSCrypto_OK) {
		    return err;
		}
		hs->sha256.length += 8*64;
		hs->sha256.curlen = 0;
	    }
	}
    }
    return NBSCrypto_OK;
}

int sha512_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;
    if (hs->sha512.curlen > sizeof(hs->sha512.buf)) {
	return NBSCrypto_ERROR;
    }
    if ((hs->sha512.length + inlen * 8) < hs->sha512.length) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	if (hs->sha512.curlen == 0 && inlen >= 128) {
	    if ((err = _sha512_compress(hs, in)) != NBSCrypto_OK) {
		return err;
	    }
	    hs->sha512.length += 128 * 8;
	    in		+= 128;
	    inlen	-= 128;
	} else {
	    n = MIN(inlen, (128 - hs->sha512.curlen));
	    memcpy(hs->sha512.buf + hs->sha512.curlen, in, (size_t)n);
	    hs->sha512.curlen += n;
	    in += n;
	    inlen -= n;
	    if (hs->sha512.curlen == 128) {
		if ((err = _sha512_compress(hs, hs->sha512.buf)) != NBSCrypto_OK) {
		    return err;
		}
		hs->sha512.length += 8*128;
		hs->sha512.curlen = 0;
	    }
	}
    }
    return NBSCrypto_OK;
}

int sha224_done(hash_state *hs, unsigned char *out)
{
    unsigned char buf[32];
    int err;

    err = sha256_done(hs, buf);
    memcpy(out, buf, 28);

    return err;
}

int sha256_done(hash_state *hs, unsigned char *out)
{
    int i;

    if (hs->sha256.curlen >= sizeof(hs->sha256.buf)) {
	return NBSCrypto_ERROR;
    }

    hs->sha256.length += hs->sha256.curlen * 8;
    hs->sha256.buf[hs->sha256.curlen++] = (unsigned char)0x80;

    if (hs->sha256.curlen > 56) {
	while (hs->sha256.curlen < 64) {
	    hs->sha256.buf[hs->sha256.curlen++] = (unsigned char)0;
	}
	_sha256_compress(hs, hs->sha256.buf);
	hs->sha256.curlen = 0;
    }

    while (hs->sha256.curlen < 56) {
	hs->sha256.buf[hs->sha256.curlen++] = (unsigned char)0;
    }

    STORE64H(hs->sha256.length, hs->sha256.buf+56);
    _sha256_compress(hs, hs->sha256.buf);

    for (i = 0; i < 8; i++) {
	STORE32H(hs->sha256.state[i], out+(4*i));
    }

    return NBSCrypto_OK;
}

int sha384_done(hash_state *hs, unsigned char *out)
{
    unsigned char buf[64];

    if (hs->sha512.curlen >= sizeof(hs->sha512.buf)) {
	return NBSCrypto_ERROR;
    }

    sha512_done(hs, buf);
    memcpy(out, buf, 48);

    return NBSCrypto_OK;
}

int sha512_done(hash_state *hs, unsigned char *out)
{
    int i;

    if (hs->sha512.curlen >= sizeof(hs->sha512.buf)) {
	return NBSCrypto_ERROR;
    }

    hs->sha512.length += hs->sha512.curlen * CONST64(8);
    hs->sha512.buf[hs->sha512.curlen++] = (unsigned char)0x80;

    if (hs->sha512.curlen > 112) {
	while (hs->sha512.curlen < 128) {
	    hs->sha512.buf[hs->sha512.curlen++] = (unsigned char)0;
	}
	_sha512_compress(hs, hs->sha512.buf);
	hs->sha512.curlen = 0;
    }

    while (hs->sha512.curlen < 120) {
	hs->sha512.buf[hs->sha512.curlen++] = (unsigned char)0;
    }

    STORE64H(hs->sha512.length, hs->sha512.buf+120);
    _sha512_compress(hs, hs->sha512.buf);

    for (i = 0; i < 8; i++) {
	STORE64H(hs->sha512.state[i], out+(8*i));
    }

    return NBSCrypto_OK;
}

int sha512_224_done(hash_state *hs, unsigned char *out)
{
    unsigned char buf[64];

    if (hs->sha512.curlen >= sizeof(hs->sha512.buf)) {
	return NBSCrypto_ERROR;
    }

    sha512_done(hs, buf);
    memcpy(out, buf, 28);

    return NBSCrypto_OK;
}

int sha512_256_done(hash_state *hs, unsigned char *out)
{
    unsigned char buf[64];

    if (hs->sha512.curlen >= sizeof(hs->sha512.buf)) {
	return NBSCrypto_ERROR;
    }

    sha512_done(hs, buf);
    memcpy(out, buf, 32);

    return NBSCrypto_OK;
}
