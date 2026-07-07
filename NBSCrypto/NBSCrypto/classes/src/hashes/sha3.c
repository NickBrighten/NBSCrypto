//
//	sha3.c
//	Authors / Developers		: Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche
//	Last Modified (Original)	: 2012
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor sha3_224_desc =
{
    "sha3-224",
    10380224,
    28,
    144,
    &sha3_224_init,
    &sha3_process,
    &sha3_done,
    NULL
};

const struct hash_descriptor sha3_256_desc =
{
    "sha3-256",
    10380256,
    32,
    136,
    &sha3_256_init,
    &sha3_process,
    &sha3_done,
    NULL
};

const struct hash_descriptor sha3_384_desc =
{
    "sha3-384",
    10380384,
    48,
    104,
    &sha3_384_init,
    &sha3_process,
    &sha3_done,
    NULL
};

const struct hash_descriptor sha3_512_desc =
{
    "sha3-512",
    10380512,
    64,
    72,
    &sha3_512_init,
    &sha3_process,
    &sha3_done,
    NULL
};

const struct hash_descriptor keccak_224_desc =
{
    "keccak-224",
    10240224,
    28,
    144,
    &sha3_224_init,
    &sha3_process,
    &keccak_done,
    NULL
};

const struct hash_descriptor keccak_256_desc =
{
    "keccak-256",
    10240256,
    32,
    136,
    &sha3_256_init,
    &sha3_process,
    &keccak_done,
    NULL
};

const struct hash_descriptor keccak_384_desc =
{
    "keccak-384",
    10240384,
    48,
    104,
    &sha3_384_init,
    &sha3_process,
    &keccak_done,
    NULL
};

const struct hash_descriptor keccak_512_desc =
{
    "keccak-512",
    10240512,
    64,
    72,
    &sha3_512_init,
    &sha3_process,
    &keccak_done,
    NULL
};

const struct hash_descriptor shake_128_desc =
{
    "shake-128",
    10400128,
    16,
    168,
    &sha3_shake_128_init,
    &sha3_process,
    &keccak_done,
    NULL
};

const struct hash_descriptor shake_256_desc =
{
    "shake-256",
    10400256,
    32,
    136,
    &sha3_shake_256_init,
    &sha3_process,
    &keccak_done,
    NULL
};


#pragma mark - DEFINES
#define SHA3_SPONGE_WORDS 25
#define SHA3_ROUNDS 24

#define STORE64L(x,y)										\
    do {(y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);	\
	(y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);	\
	(y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);	\
	(y)[1] = (unsigned char)(((x)>> 8)&255); (y)[0] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD64L(x, y)						\
    do {x = (((unsigned long long)((y)[7] & 255))<<56)|		\
	    (((unsigned long long)((y)[6] & 255))<<48)|		\
	    (((unsigned long long)((y)[5] & 255))<<40)|		\
	    (((unsigned long long)((y)[4] & 255))<<32)|		\
	    (((unsigned long long)((y)[3] & 255))<<24)|		\
	    (((unsigned long long)((y)[2] & 255))<<16)|		\
	    (((unsigned long long)((y)[1] & 255))<< 8)|		\
	    (((unsigned long long)((y)[0] & 255)));		\
} while(0)

#define ROL64(x, y) ((((x)<<((unsigned long long)(y)&63)) | (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>(((unsigned long long)64-((y)&63))&63))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define CONST64(n) n ## ULL


static const unsigned long long s_rndc[24] = {
    CONST64(0x0000000000000001), CONST64(0x0000000000008082),
    CONST64(0x800000000000808a), CONST64(0x8000000080008000),
    CONST64(0x000000000000808b), CONST64(0x0000000080000001),
    CONST64(0x8000000080008081), CONST64(0x8000000000008009),
    CONST64(0x000000000000008a), CONST64(0x0000000000000088),
    CONST64(0x0000000080008009), CONST64(0x000000008000000a),
    CONST64(0x000000008000808b), CONST64(0x800000000000008b),
    CONST64(0x8000000000008089), CONST64(0x8000000000008003),
    CONST64(0x8000000000008002), CONST64(0x8000000000000080),
    CONST64(0x000000000000800a), CONST64(0x800000008000000a),
    CONST64(0x8000000080008081), CONST64(0x8000000000008080),
    CONST64(0x0000000080000001), CONST64(0x8000000080008008)
};

static const unsigned s_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned s_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};




#pragma mark - INLINE
static inline void _sha3_rnd(unsigned long long s[25])
{
    int i, j, round;
    unsigned long long t, bc[5];

    for(round = 0; round < SHA3_ROUNDS; round++) {
	for(i = 0; i < 5; i++) {
	    bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
	}
	for(i = 0; i < 5; i++) {
	    t = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
	    for(j = 0; j < 25; j += 5) {
		s[j + i] ^= t;
	    }
	}

	t = s[1];
	for(i = 0; i < 24; i++) {
	    j = s_piln[i];
	    bc[0] = s[j];
	    s[j] = ROL64(t, s_rotc[i]);
	    t = bc[0];
	}

	for(j = 0; j < 25; j += 5) {
	    for(i = 0; i < 5; i++) {
		bc[i] = s[j + i];
	    }
	    for(i = 0; i < 5; i++) {
		s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
	    }
	}

	s[0] ^= s_rndc[round];
    }
}

static inline int _sha3_shake_init(hash_state *hs, int num)
{
    if (num != 128 && num != 256) return NBSCrypto_ERROR;
    memset(&hs->sha3, 0, sizeof(hs->sha3));
    hs->sha3.capacity_words = (unsigned short)(2 * num / (8 * sizeof(unsigned long long)));
    return NBSCrypto_OK;
}

static inline int _sha3_done(hash_state *hs, unsigned char *hash, unsigned long long pad)
{
    unsigned i;

    hs->sha3.s[hs->sha3.word_index] ^= (hs->sha3.saved ^ (pad << (hs->sha3.byte_index * 8)));
    hs->sha3.s[SHA3_SPONGE_WORDS - hs->sha3.capacity_words - 1] ^= CONST64(0x8000000000000000);
    _sha3_rnd(hs->sha3.s);

    for(i = 0; i < SHA3_SPONGE_WORDS; i++) {
	STORE64L(hs->sha3.s[i], hs->sha3.sb + i * 8);
    }

    memcpy(hash, hs->sha3.sb, hs->sha3.capacity_words * 4);
    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int sha3_224_init(hash_state *hs)
{
    memset(&hs->sha3, 0, sizeof(hs->sha3));
    hs->sha3.capacity_words = 2 * 224 / (8 * sizeof(unsigned long long));
    return NBSCrypto_OK;
}

int sha3_256_init(hash_state *hs)
{
    memset(&hs->sha3, 0, sizeof(hs->sha3));
    hs->sha3.capacity_words = 2 * 256 / (8 * sizeof(unsigned long long));
    return NBSCrypto_OK;
}

int sha3_384_init(hash_state *hs)
{
    memset(&hs->sha3, 0, sizeof(hs->sha3));
    hs->sha3.capacity_words = 2 * 384 / (8 * sizeof(unsigned long long));
    return NBSCrypto_OK;
}

int sha3_512_init(hash_state *hs)
{
    memset(&hs->sha3, 0, sizeof(hs->sha3));
    hs->sha3.capacity_words = 2 * 512 / (8 * sizeof(unsigned long long));
    return NBSCrypto_OK;
}

int sha3_shake_128_init(hash_state *hs)
{
    return _sha3_shake_init(hs, 128);
}

int sha3_shake_256_init(hash_state *hs)
{
    return _sha3_shake_init(hs, 256);
}

int sha3_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned old_tail = (8 - hs->sha3.byte_index) & 7;
    unsigned long words;
    unsigned long tail;
    unsigned long i;

    if (inlen == 0) return NBSCrypto_OK;

    if(inlen < old_tail) {
	while (inlen--) hs->sha3.saved |= (unsigned long long) (*(in++)) << ((hs->sha3.byte_index++) * 8);
	return NBSCrypto_OK;
    }

    if(old_tail){
	inlen -= old_tail;
	while (old_tail--) hs->sha3.saved |= (unsigned long long) (*(in++)) << ((hs->sha3.byte_index++) * 8);
	hs->sha3.s[hs->sha3.word_index] ^= hs->sha3.saved;
	hs->sha3.byte_index = 0;
	hs->sha3.saved = 0;

	if(++hs->sha3.word_index == (SHA3_SPONGE_WORDS - hs->sha3.capacity_words)) {
	    _sha3_rnd(hs->sha3.s);
	    hs->sha3.word_index = 0;
	}
    }

    words = inlen / sizeof(unsigned long long);
    tail = inlen - words * sizeof(unsigned long long);

    for(i = 0; i < words; i++, in += sizeof(unsigned long long)) {
	unsigned long long t;
	LOAD64L(t, in);
	hs->sha3.s[hs->sha3.word_index] ^= t;

	if(++hs->sha3.word_index == (SHA3_SPONGE_WORDS - hs->sha3.capacity_words)) {
	    _sha3_rnd(hs->sha3.s);
	    hs->sha3.word_index = 0;
	}
    }

    while (tail--) {
	hs->sha3.saved |= (unsigned long long) (*(in++)) << ((hs->sha3.byte_index++) * 8);
    }
    return NBSCrypto_OK;
}

int sha3_done(hash_state *hs, unsigned char *out)
{
    return _sha3_done(hs, out, CONST64(0x06));
}

int keccak_done(hash_state *hs, unsigned char *out)
{
    return _sha3_done(hs, out, CONST64(0x01));
}

int sha3_shake_done(hash_state *hs, unsigned char *out, unsigned long outlen)
{
    unsigned long idx;
    unsigned i;

    if (outlen == 0) return NBSCrypto_OK;

    if (!hs->sha3.xof_flag) {
	hs->sha3.s[hs->sha3.word_index] ^= (hs->sha3.saved ^ (CONST64(0x1F) << (hs->sha3.byte_index * 8)));
	hs->sha3.s[SHA3_SPONGE_WORDS - hs->sha3.capacity_words - 1] ^= CONST64(0x8000000000000000);
	_sha3_rnd(hs->sha3.s);

	for(i = 0; i < SHA3_SPONGE_WORDS; i++) {
	    STORE64L(hs->sha3.s[i], hs->sha3.sb + i * 8);
	}
	hs->sha3.byte_index = 0;
	hs->sha3.xof_flag = 1;
    }

    for (idx = 0; idx < outlen; idx++) {
	if(hs->sha3.byte_index >= (SHA3_SPONGE_WORDS - hs->sha3.capacity_words) * 8) {
	    _sha3_rnd(hs->sha3.s);
	    for(i = 0; i < SHA3_SPONGE_WORDS; i++) {
		STORE64L(hs->sha3.s[i], hs->sha3.sb + i * 8);
	    }
	    hs->sha3.byte_index = 0;
	}
	out[idx] = hs->sha3.sb[hs->sha3.byte_index++];
    }
    return NBSCrypto_OK;
}
