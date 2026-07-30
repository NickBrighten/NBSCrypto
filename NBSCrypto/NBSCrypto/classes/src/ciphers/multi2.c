//
//	multi2.c
//	Authors / Developers		: Hitachi
//	Last Modified (Original)	: 1988
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor multi2_desc =
{
    "multi2",
    19,
    40, 40, 8, 128,
    &multi2_setup,
    &multi2_encrypt,
    &multi2_decrypt,
    &multi2_done
};




#pragma mark - DEFINES

#define LOAD32H(x, y)				\
    do { x =((unsigned)((y)[0] & 255)<<24) |	\
	    ((unsigned)((y)[1] & 255)<<16) |	\
	    ((unsigned)((y)[2] & 255)<< 8) |	\
	    ((unsigned)((y)[3] & 255));		\
} while(0)

#define STORE32H(x, y)					\
    do {(y)[0] = (unsigned char)(((x)>>24)&255);	\
	(y)[1] = (unsigned char)(((x)>>16)&255);	\
	(y)[2] = (unsigned char)(((x)>> 8)&255);	\
	(y)[3] = (unsigned char)((x)&255);		\
} while(0)

#define ROL(x, y) ((((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFFUL)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFFUL)




#pragma mark - INLINE
static inline void _pi1(unsigned *p)
{
    p[1] ^= p[0];
}

static inline void _pi2(unsigned *p, const unsigned *k)
{
    unsigned t;
    t = (p[1] + k[0]) & 0xFFFFFFFFUL;
    t = (ROL(t, 1) + t - 1)  & 0xFFFFFFFFUL;
    t = (ROL(t, 4) ^ t)  & 0xFFFFFFFFUL;
    p[0] ^= t;
}

static inline void _pi3(unsigned *p, const unsigned *k)
{
    unsigned t;
    t = p[0] + k[1];
    t = (ROL(t, 2) + t + 1)  & 0xFFFFFFFFUL;
    t = (ROL(t, 8) ^ t)  & 0xFFFFFFFFUL;
    t = (t + k[2])  & 0xFFFFFFFFUL;
    t = (ROL(t, 1) - t)  & 0xFFFFFFFFUL;
    t = ROL(t, 16) ^ (p[0] | t);
    p[1] ^= t;
}

static inline void _pi4(unsigned *p, const unsigned *k)
{
    unsigned t;
    t = (p[1] + k[3])  & 0xFFFFFFFFUL;
    t = (ROL(t, 2) + t + 1)  & 0xFFFFFFFFUL;
    p[0] ^= t;
}

static inline void _setup(const unsigned *dk, const unsigned *k, unsigned *uk)
{
    int n, t;
    unsigned p[2];

    p[0] = dk[0]; p[1] = dk[1];

    t = 4;
    n = 0;
    _pi1(p);
    _pi2(p, k);
    uk[n++] = p[0];
    _pi3(p, k);
    uk[n++] = p[1];
    _pi4(p, k);
    uk[n++] = p[0];
    _pi1(p);
    uk[n++] = p[1];
    _pi2(p, k+t);
    uk[n++] = p[0];
    _pi3(p, k+t);
    uk[n++] = p[1];
    _pi4(p, k+t);
    uk[n++] = p[0];
    _pi1(p);
    uk[n++] = p[1];
}

static inline void _encrypt(unsigned *p, int N, const unsigned *uk)
{
    int n, t;
    for (t = n = 0; ; ) {
	_pi1(p); if (++n == N) break;
	_pi2(p, uk+t); if (++n == N) break;
	_pi3(p, uk+t); if (++n == N) break;
	_pi4(p, uk+t); if (++n == N) break;
	t ^= 4;
    }
}

static inline void _decrypt(unsigned *p, int N, const unsigned *uk)
{
    int n, t;
    for (t = 4*(((N-1)>>2)&1), n = N; ;  ) {
	switch (n<=4 ? n : ((n-1)%4)+1) {
	    case 4: _pi4(p, uk+t); --n;
	    case 3: _pi3(p, uk+t); --n;
	    case 2: _pi2(p, uk+t); --n;
	    case 1: _pi1(p); --n; break;
	    case 0: return;
	}
	t ^= 4;
    }
}




#pragma mark - FUNCTIONS
int multi2_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    int x;
    unsigned sk[8], dk[2];

    if (keylen != 40) return NBSCrypto_ERROR;
    if (num_rounds == 0) num_rounds = 128;

    cs->multi2.N = num_rounds;
    for (x = 0; x < 8; x++) {
	LOAD32H(sk[x], key + x*4);
    }
    LOAD32H(dk[0], key + 32);
    LOAD32H(dk[1], key + 36);
    _setup(dk, sk, cs->multi2.uk);

    zeromem(sk, sizeof(sk));
    zeromem(dk, sizeof(dk));

    return NBSCrypto_OK;
}

int multi2_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    unsigned p[2];

    LOAD32H(p[0], pt);
    LOAD32H(p[1], pt+4);
    _encrypt(p, cs->multi2.N, cs->multi2.uk);
    STORE32H(p[0], ct);
    STORE32H(p[1], ct+4);

    return NBSCrypto_OK;
}

int multi2_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    unsigned p[2];

    LOAD32H(p[0], ct);
    LOAD32H(p[1], ct+4);
    _decrypt(p, cs->multi2.N, cs->multi2.uk);
    STORE32H(p[0], pt);
    STORE32H(p[1], pt+4);

    return NBSCrypto_OK;
}

void multi2_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->multi2));
}
