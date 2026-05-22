//
//	md2.c
//	Authors / Developers		: Ronald L. Rivest
//	Last Modified (Original)	: 1988
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor md2_desc =
{
    "md2",
    167,
    16,
    16,
    &md2_init,
    &md2_process,
    &md2_done,
    NULL
};




#pragma mark - DEFINES
#define MIN(x, y) (((x)<(y))?(x):(y))


static const unsigned char PI_SUBST[256] = {
     41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,  19,
     98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,  76, 130, 202,
     30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
    190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
    169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16, 137,  11,  34,  95,  33,
    128, 127,  93, 154,  90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
    255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
     79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,
     69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
     27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
     85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
     44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77,  82,
    106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
    120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
    242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
     49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131,  20
};




#pragma mark - INLINE
static inline void _md2_chksum(hash_state *hs)
{
    int j;
    unsigned char L;
    L = hs->md2.chksum[15];
    for (j = 0; j < 16; j++) {
	L = (hs->md2.chksum[j] ^= PI_SUBST[(int)(hs->md2.buf[j] ^ L)] & 255);
    }
}

static inline void _md2_compress(hash_state *hs)
{
    int j, k;
    unsigned char t;

    for (j = 0; j < 16; j++) {
	hs->md2.X[16+j] = hs->md2.buf[j];
	hs->md2.X[32+j] = hs->md2.X[j] ^ hs->md2.X[16+j];
    }

    t = (unsigned char)0;

    for (j = 0; j < 18; j++) {
	for (k = 0; k < 48; k++) {
	    t = (hs->md2.X[k] ^= PI_SUBST[(int)(t & 255)]);
	}
	t = (t + (unsigned char)j) & 255;
    }
}




#pragma mark - FUNCTIONS
int md2_init(hash_state *hs)
{
    zeromem(hs->md2.X, sizeof(hs->md2.X));
    zeromem(hs->md2.chksum, sizeof(hs->md2.chksum));
    zeromem(hs->md2.buf, sizeof(hs->md2.buf));
    hs->md2.curlen = 0;

    return NBSCrypto_OK;
}

int md2_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    if (hs->md2.curlen > sizeof(hs->md2.buf)) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	n = MIN(inlen, (16 - hs->md2.curlen));
	memcpy(hs->md2.buf + hs->md2.curlen, in, (size_t)n);
	hs->md2.curlen += n;
	in             += n;
	inlen          -= n;

	if (hs->md2.curlen == 16) {
	    _md2_compress(hs);
	    _md2_chksum(hs);
	    hs->md2.curlen = 0;
	}
    }

    return NBSCrypto_OK;
}

int md2_done(hash_state *hs, unsigned char *out)
{
    unsigned long i, k;

    if (hs->md2.curlen >= sizeof(hs->md2.buf)) {
	return NBSCrypto_ERROR;
    }

    k = 16 - hs->md2.curlen;
    for (i = hs->md2.curlen; i < 16; i++) {
	hs->md2.buf[i] = (unsigned char)k;
    }

    _md2_compress(hs);
    _md2_chksum(hs);

    memcpy(hs->md2.buf, hs->md2.chksum, 16);
    _md2_compress(hs);

    memcpy(out, hs->md2.X, 16);

    return NBSCrypto_OK;
}
