//
//	sha3.c
//	Authors / Developers		: Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles van Assche
//	Original			: 2012

//
//	Contributors
//	KangarooTwelve		-	Ronny Van Keer, Benoît Viguier (2016)
//
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor sha3_224_desc =
{
    "sha3-224",
    203,
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
    204,
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
    205,
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
    206,
    64,
    72,
    &sha3_512_init,
    &sha3_process,
    &sha3_done,
    NULL
};

const struct hash_descriptor kangarootwelve_128_desc =
{
    "kangarootwelve-128",
    150,
    16,
    168,
    &sha3_kangarootwelve_128_init,
    &sha3_kangarootwelve_process,
    &sha3_kangarootwelve_128_done,
    NULL
};

const struct hash_descriptor kangarootwelve_256_desc =
{
    "kangarootwelve-256",
    151,
    32,
    136,
    &sha3_kangarootwelve_256_init,
    &sha3_kangarootwelve_process,
    &sha3_kangarootwelve_256_done,
    NULL
};
const struct hash_descriptor keccak_224_desc =
{
    "keccak-224",
    152,
    28,
    144,
    &sha3_224_init,
    &sha3_process,
    &sha3_keccak_done,
    NULL
};

const struct hash_descriptor keccak_256_desc =
{
    "keccak-256",
    153,
    32,
    136,
    &sha3_256_init,
    &sha3_process,
    &sha3_keccak_done,
    NULL
};

const struct hash_descriptor keccak_384_desc =
{
    "keccak-384",
    154,
    48,
    104,
    &sha3_384_init,
    &sha3_process,
    &sha3_keccak_done,
    NULL
};

const struct hash_descriptor keccak_512_desc =
{
    "keccak-512",
    155,
    64,
    72,
    &sha3_512_init,
    &sha3_process,
    &sha3_keccak_done,
    NULL
};

const struct hash_descriptor shake_128_desc =
{
    "shake-128",
    212,
    16,
    168,
    &sha3_shake_128_init,
    &sha3_process,
    &sha3_keccak_done,
    NULL
};

const struct hash_descriptor shake_256_desc =
{
    "shake-256",
    213,
    32,
    136,
    &sha3_shake_256_init,
    &sha3_process,
    &sha3_keccak_done,
    NULL
};




#pragma mark - DEFINES
#define SHA3_SPONGE_WORDS 25
#define SHA3_ROUNDS 24
#define NBS_ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

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

static const unsigned char kangaroo_twelve_filler[] = {
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

typedef void (*process_fn)(unsigned long long s[25]);




#pragma mark - INLINE
static inline void _keccak_f(unsigned long long s[25], int max_rounds, int rc_offset)
{
    int i, j, round;
    unsigned long long t, bc[5];

    for(round = 0; round < max_rounds; round++) {
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
	s[0] ^= s_rndc[rc_offset + round];
    }
}

static inline void _keccakf(unsigned long long s[25])
{
    _keccak_f(s, 24, 0);
}

static inline void _keccak_turbo_f(unsigned long long s[25])
{
    _keccak_f(s, 12, 12);
}

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

static inline int _sha3_shake_init(struct sha3_state *sha3, int num)
{
    if (num != 128 && num != 256) return NBSCrypto_ERROR;
    memset(sha3, 0, sizeof(*sha3));
    sha3->capacity_words = 2 * num / (8 * sizeof(unsigned long long));
    return NBSCrypto_OK;
}

static inline int _sha3_kangarootwelve_init(hash_state *hs, int num)
{
    int err;

    if ((err = _sha3_shake_init(&hs->kangarootwelve.outer, num)) != NBSCrypto_OK) return err;
    if ((err = _sha3_shake_init(&hs->kangarootwelve.inner, num)) != NBSCrypto_OK) return err;
    hs->kangarootwelve.blocks_count = 0;
    hs->kangarootwelve.customization_len = 0;
    hs->kangarootwelve.remaining = 8 * 1024;
    hs->kangarootwelve.phase = 0;
    hs->kangarootwelve.finished = 0;
    return NBSCrypto_OK;
}

static inline int _sha3_process(struct sha3_state *sha3, const unsigned char *in, unsigned long inlen, process_fn proc_f)
{
    unsigned old_tail;
    unsigned long i, tail, words;

    if (inlen == 0) return NBSCrypto_OK;

    old_tail = (8 - sha3->byte_index) & 7;

    if(inlen < old_tail) {
	while (inlen--) sha3->saved |= (unsigned long long) (*(in++)) << ((sha3->byte_index++) * 8);
	return NBSCrypto_OK;
    }

    if(old_tail) {
	inlen -= old_tail;
	while (old_tail--) sha3->saved |= (unsigned long long) (*(in++)) << ((sha3->byte_index++) * 8);
	sha3->s[sha3->word_index] ^= sha3->saved;
	sha3->byte_index = 0;
	sha3->saved = 0;
	if(++sha3->word_index == (25 - sha3->capacity_words)) {
	    proc_f(sha3->s);
	    sha3->word_index = 0;
	}
    }

    words = inlen / sizeof(unsigned long long);
    tail = inlen - words * sizeof(unsigned long long);

    for(i = 0; i < words; i++, in += sizeof(unsigned long long)) {
	unsigned long long t;
	LOAD64L(t, in);
	sha3->s[sha3->word_index] ^= t;
	if(++sha3->word_index == (25 - sha3->capacity_words)) {
	    proc_f(sha3->s);
	    sha3->word_index = 0;
	}
    }

    while (tail--) {
	sha3->saved |= (unsigned long long) (*(in++)) << ((sha3->byte_index++) * 8);
    }
    return NBSCrypto_OK;
}

static inline int _sha3_turbo_shake_process(struct sha3_state *sha3, const unsigned char *in, unsigned long inlen)
{
    return _sha3_process(sha3, in, inlen, _keccak_turbo_f);
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

static inline int _sha3_shake_done(struct sha3_state *sha3, unsigned char *out, unsigned long outlen, unsigned char domain, process_fn proc_f)
{
    unsigned long idx;
    unsigned i;

    if (outlen == 0) return NBSCrypto_OK;

    if (!sha3->xof_flag) {
	sha3->s[sha3->word_index] ^= (sha3->saved ^ (((unsigned long long)(domain)) << (sha3->byte_index * 8)));
	sha3->s[SHA3_SPONGE_WORDS - sha3->capacity_words - 1] ^= CONST64(0x8000000000000000);
	proc_f(sha3->s);

	for(i = 0; i < SHA3_SPONGE_WORDS; i++) {
	    STORE64L(sha3->s[i], sha3->sb + i * 8);
	}
	sha3->byte_index = 0;
	sha3->xof_flag = 1;
    }

    for (idx = 0; idx < outlen; idx++) {
	if(sha3->byte_index >= (SHA3_SPONGE_WORDS - sha3->capacity_words) * 8) {
	    proc_f(sha3->s);

	    for(i = 0; i < SHA3_SPONGE_WORDS; i++) {
		STORE64L(sha3->s[i], sha3->sb + i * 8);
	    }
	    sha3->byte_index = 0;
	}
	out[idx] = sha3->sb[sha3->byte_index++];
    }
    return NBSCrypto_OK;
}

static inline int _sha3_turbo_shake_done(struct sha3_state *sha3, unsigned char *out, unsigned long outlen)
{
    return _sha3_shake_done(sha3, out, outlen, 0x1f, _keccak_turbo_f);
}

static inline int _sha3_kangarootwelve_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    int err;
    int variant;
    int digest_len;
    unsigned char digest_buf[64];
    unsigned long rem;
    unsigned long amount;

    if (hs->kangarootwelve.phase == 0)
    {
	rem = hs->kangarootwelve.remaining;
	amount = rem < inlen ? rem : inlen;
	hs->kangarootwelve.remaining -= amount;
	if ((err = _sha3_turbo_shake_process(&hs->kangarootwelve.outer, in, amount)) != NBSCrypto_OK) return err;
	in += amount;
	inlen -= amount;
	if (hs->kangarootwelve.remaining == 0 && inlen != 0){
	    hs->kangarootwelve.remaining = 8 * 1024;
	    hs->kangarootwelve.phase = 1;
	    hs->kangarootwelve.blocks_count += 1;
	    if ((err = _sha3_turbo_shake_process(&hs->kangarootwelve.outer, kangaroo_twelve_filler, sizeof(kangaroo_twelve_filler))) != NBSCrypto_OK) return err;
	}
    }
    if (hs->kangarootwelve.phase == 1)
    {
	do
	{
	    rem = hs->kangarootwelve.remaining;
	    amount = rem < inlen ? rem : inlen;
	    hs->kangarootwelve.remaining -= amount;
	    if ((err = _sha3_turbo_shake_process(&hs->kangarootwelve.inner, in, amount)) != NBSCrypto_OK) return err;
	    in += amount;
	    inlen -= amount;
	    if (hs->kangarootwelve.remaining == 0 && inlen != 0){
		hs->kangarootwelve.remaining = 8 * 1024;
		hs->kangarootwelve.blocks_count += 1;
		variant = hs->kangarootwelve.outer.capacity_words == 4 ? 128 : 256;
		digest_len = variant == 128 ? 32 : 64;
		if ((err = _sha3_shake_done(&hs->kangarootwelve.inner, digest_buf, digest_len, 0x0b, _keccak_turbo_f)) != NBSCrypto_OK) return err;
		if ((err = _sha3_shake_init(&hs->kangarootwelve.inner, variant)) != NBSCrypto_OK) return err;
		if ((err = _sha3_turbo_shake_process(&hs->kangarootwelve.outer, digest_buf, digest_len)) != NBSCrypto_OK) return err;
	    }
	} while (inlen != 0);
    }
    return NBSCrypto_OK;
}

int _sha3_kangarootwelve_done(hash_state *hs, unsigned char *out, unsigned long outlen)
{
    int couner_len, digest_len, err, variant;
    unsigned char couner_buf[sizeof(unsigned long long) + 1], digest_buf[64], domain, ffff[2];

    if (hs->kangarootwelve.finished == 0){
	hs->kangarootwelve.finished = 1;
	couner_len = 0;
	while (hs->kangarootwelve.customization_len != 0){
	    couner_buf[NBS_ARRAY_SIZE(couner_buf) - 1 - 1 - couner_len] = hs->kangarootwelve.customization_len & 0xff;
	    hs->kangarootwelve.customization_len >>= 8;
	    ++couner_len;
	}
	couner_buf[NBS_ARRAY_SIZE(couner_buf) - 1] = couner_len;
	if ((err = _sha3_kangarootwelve_process(hs, &couner_buf[NBS_ARRAY_SIZE(couner_buf) - 1 - couner_len], couner_len + 1)) != NBSCrypto_OK) return err;
	if(hs->kangarootwelve.phase != 0){
	    variant = hs->kangarootwelve.outer.capacity_words == 4 ? 128 : 256;
	    digest_len = variant == 128 ? 32 : 64;
	    if ((err = _sha3_shake_done(&hs->kangarootwelve.inner, digest_buf, digest_len, 0x0b, _keccak_turbo_f)) != NBSCrypto_OK) return err;
	    if ((err = _sha3_turbo_shake_process(&hs->kangarootwelve.outer, digest_buf, digest_len)) != NBSCrypto_OK) return err;
	    couner_len = 0;
	    while (hs->kangarootwelve.blocks_count != 0){
		couner_buf[NBS_ARRAY_SIZE(couner_buf) - 1 - 1 - couner_len] = hs->kangarootwelve.blocks_count & 0xff;
		hs->kangarootwelve.blocks_count >>= 8;
		++couner_len;
	    }
	    couner_buf[NBS_ARRAY_SIZE(couner_buf) - 1] = couner_len;
	    if ((err = _sha3_turbo_shake_process(&hs->kangarootwelve.outer, &couner_buf[NBS_ARRAY_SIZE(couner_buf) - 1 - couner_len], couner_len + 1)) != NBSCrypto_OK) return err;
	    ffff[0] = 0xff;
	    ffff[1] = 0xff;
	    if ((err = _sha3_turbo_shake_process(&hs->kangarootwelve.outer, ffff, NBS_ARRAY_SIZE(ffff))) != NBSCrypto_OK) return err;
	}
    }
    domain = hs->kangarootwelve.phase == 0 ? 0x07 : 0x06;
    return _sha3_shake_done(&hs->kangarootwelve.outer, out, outlen, domain, _keccak_turbo_f);
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

int sha3_kangarootwelve_128_init(hash_state *hs)
{
    return _sha3_kangarootwelve_init(hs, 128);
}

int sha3_kangarootwelve_256_init(hash_state *hs)
{
    return _sha3_kangarootwelve_init(hs, 256);
}

int sha3_shake_128_init(hash_state *hs)
{
    return _sha3_shake_init(&hs->sha3, 128);
}

int sha3_shake_256_init(hash_state *hs)
{
    return _sha3_shake_init(&hs->sha3, 256);
}

int sha3_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    return _sha3_process(&hs->sha3, in, inlen, _keccakf);
}

int sha3_kangarootwelve_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    return _sha3_kangarootwelve_process(hs, in, inlen);
}

int sha3_turbo_shake_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    return _sha3_turbo_shake_process(&hs->sha3, in, inlen);
}

int sha3_done(hash_state *hs, unsigned char *out)
{
    return _sha3_done(hs, out, CONST64(0x06));
}

int sha3_kangarootwelve_128_done(hash_state *hs, unsigned char *out)
{
    return _sha3_kangarootwelve_done(hs, out, 16);
}

int sha3_kangarootwelve_256_done(hash_state *hs, unsigned char *out)
{
    return _sha3_kangarootwelve_done(hs, out, 32);
}

int sha3_keccak_done(hash_state *hs, unsigned char *out)
{
    return _sha3_done(hs, out, CONST64(0x01));
}

int sha3_shake_done(hash_state *hs, unsigned char *out, unsigned long outlen)
{
    return _sha3_shake_done(&hs->sha3, out, outlen, 0x1f, _keccakf);
}

int sha3_shake_done_ex(hash_state *hs, unsigned char *out, unsigned long outlen, unsigned char domain)
{
    return _sha3_shake_done(&hs->sha3, out, outlen, domain, _keccakf);
}

int sha3_turbo_shake_done(hash_state *hs, unsigned char *out, unsigned long outlen)
{
    return _sha3_turbo_shake_done(&hs->sha3, out, outlen);
}
