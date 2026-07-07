//
//	kasumi.c
//	Authors / Developers		: Mitsubishi Electric
//	Last Modified (Original)	: 1999
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct cipher_descriptor kasumi_desc =
{
    "kasumi",
    13,
    16, 16, 8, 8,
    &kasumi_setup,
    &kasumi_encrypt,
    &kasumi_decrypt,
    &kasumi_done
};




#pragma mark - DEFINES

#define ROL16(x, y) ((((x)<<(y)) | ((x)>>(16-(y)))) & 0xffff)

#define STORE32(x, y)										\
    do {(y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);	\
	(y)[2] = (unsigned char)(((x)>> 8)&255); (y)[3] = (unsigned char)((x)&255);		\
} while(0)

#define LOAD32(x, y)										\
    do {x = ((unsigned)((y)[0] & 255)<<24) | ((unsigned)((y)[1] & 255)<<16) |			\
	    ((unsigned)((y)[2] & 255)<< 8) | ((unsigned)((y)[3] & 255));			\
} while(0)




#pragma mark - INLINE
static inline unsigned _FI(unsigned in, unsigned subkey)
{
    unsigned nine, seven;
    static const unsigned S7[128] = {
	 54,  50,  62,  56,  22,  34,  94,  96,  38,   6,  63,  93,   2,  18, 123,  33,
	 55, 113,  39, 114,  21,  67,  65,  12,  47,  73,  46,  27,  25, 111, 124,  81,
	 53,   9, 121,  79,  52,  60,  58,  48, 101, 127,  40, 120, 104,  70,  71,  43,
	 20, 122,  72,  61,  23, 109,  13, 100,  77,   1,  16,   7,  82,  10, 105,  98,
	117, 116,  76,  11,  89, 106,   0, 125, 118,  99,  86,  69,  30,  57, 126,  87,
	112,  51,  17,   5,  95,  14,  90,  84,  91,   8,  35, 103,  32,  97,  28,  66,
	102,  31,  26,  45,  75,   4,  85,  92,  37,  74,  80,  49,  68,  29, 115,  44,
	 64, 107, 108,  24, 110,  83,  36,  78,  42,  19,  15,  41,  88, 119,  59,   3
    };
    static const unsigned S9[512] = {
	167, 239, 161, 379, 391, 334,   9, 338,  38, 226,  48, 358, 452, 385,  90, 397,
	183, 253, 147, 331, 415, 340,  51, 362, 306, 500, 262,  82, 216, 159, 356, 177,
	175, 241, 489,  37, 206,  17,   0, 333,  44, 254, 378,  58, 143, 220,  81, 400,
	 95,   3, 315, 245,  54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399,  76,
	165, 197, 395, 121, 257, 480, 423, 212, 240,  28, 462, 176, 406, 507, 288, 223,
	501, 407, 249, 265,  89, 186, 221, 428, 164,  74, 440, 196, 458, 421, 350, 163,
	232, 158, 134, 354,  13, 250, 491, 142, 191,  69, 193, 425, 152, 227, 366, 135,
	344, 300, 276, 242, 437, 320, 113, 278,  11, 243,  87, 317,  36,  93, 496,  27,
	487, 446, 482,  41,  68, 156, 457, 131, 326, 403, 339,  20,  39, 115, 442, 124,
	475, 384, 508,  53, 112, 170, 479, 151, 126, 169,  73, 268, 279, 321, 168, 364,
	363, 292,  46, 499, 393, 327, 324,  24, 456, 267, 157, 460, 488, 426, 309, 229,
	439, 506, 208, 271, 349, 401, 434, 236,  16, 209, 359,  52,  56, 120, 199, 277,
	465, 416, 252, 287, 246,   6,  83, 305, 420, 345, 153, 502,  65,  61, 244, 282,
	173, 222, 418,  67, 386, 368, 261, 101, 476, 291, 195, 430,  49,  79, 166, 330,
	280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417,  62, 454,
	132, 225, 203, 316, 234,  14, 301,  91, 503, 286, 424, 211, 347, 307, 140, 374,
	 35, 103, 125, 427,  19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
	 50, 116,  78, 410,  10, 205, 510, 171, 231,  45, 139, 467,  29,  86, 505,  32,
	 72,  26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473,  40, 119, 174, 355,
	185, 233, 389,  71, 448, 273, 372,  55, 110, 178, 322,  12, 469, 392, 369, 190,
	  1, 109, 375, 137, 181,  88,  75, 308, 260, 484,  98, 272, 370, 275, 412, 111,
	336, 318,   4, 504, 492, 259, 304,  77, 337, 435,  21, 357, 303, 332, 483,  18,
	 47,  85,  25, 497, 474, 289, 100, 269, 296, 478, 270, 106,  31, 104, 433,  84,
	414, 486, 394,  96,  99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,
	266, 351, 343, 144, 441, 365, 108, 298, 251,  34, 182, 509, 138, 210, 335, 133,
	311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481,  92, 404,
	485, 422, 248, 297,  23, 213, 130, 466,  22, 217, 283,  70, 294, 360, 419, 127,
	312, 377,   7, 468, 194,   2, 117, 295, 463, 258, 224, 447, 247, 187,  80, 398,
	284, 353, 105, 390, 299, 471, 470, 184,  57, 200, 348,  63, 204, 188,  33, 451,
	 97,  30, 310, 219,  94, 160, 129, 493,  64, 179, 263, 102, 189, 207, 114, 402,
	438, 477, 387, 122, 192,  42, 381,   5, 145, 118, 180, 449, 293, 323, 136, 380,
	 43,  66,  60, 455, 341, 445, 202, 432,   8, 237,  15, 376, 436, 464,  59, 461
    };

    nine  = (unsigned)(in>>7)&0x1ff;
    seven = (unsigned)(in&0x7f);

    nine   = (unsigned)(S9[nine] ^ seven);
    seven  = (unsigned)(S7[seven] ^ (nine & 0x7f));
    seven ^= (subkey>>9);
    nine  ^= (subkey&0x1ff);
    nine   = (unsigned)(S9[nine] ^ seven);
    seven  = (unsigned)(S7[seven] ^ (nine & 0x7f));
    return (unsigned)(seven<<9) + nine;
}

static inline unsigned _FO(unsigned in, int round_no, const cipher_state *cs)
{
    unsigned left, right;

    left = (unsigned)(in>>16);
    right = (unsigned) in&0xffff;

    left ^= cs->kasumi.KOi1[round_no];
    left = _FI( left, cs->kasumi.KIi1[round_no] );
    left ^= right;

    right ^= cs->kasumi.KOi2[round_no];
    right = _FI( right, cs->kasumi.KIi2[round_no] );
    right ^= left;

    left ^= cs->kasumi.KOi3[round_no];
    left = _FI( left, cs->kasumi.KIi3[round_no] );
    left ^= right;

    return (((unsigned)right)<<16)+left;
}

static inline unsigned _FL(unsigned in, int round_no, const cipher_state *cs)
{
    unsigned l, r, a, b;
    l = (unsigned)(in>>16);
    r = (unsigned)(in)&0xffff;
    a = (unsigned) (l & cs->kasumi.KLi1[round_no]);
    r ^= ROL16(a,1);
    b = (unsigned)(r | cs->kasumi.KLi2[round_no]);
    l ^= ROL16(b,1);

    return (((unsigned)l)<<16) + r;
}




#pragma mark - FUNCTIONS

int kasumi_setup(const unsigned char *key, int keylen, int num_rounds, cipher_state *cs)
{
    static const unsigned C[8] = { 0x0123,0x4567,0x89ab,0xcdef, 0xfedc,0xba98,0x7654,0x3210 };
    unsigned ukey[8], Kprime[8];
    int n;

    if (keylen != 16) {
	return NBSCrypto_ERROR;
    }

    if (num_rounds != 0 && num_rounds != 8) {
	return NBSCrypto_ERROR;
    }

    for (n = 0; n < 8; n++ ) {
	ukey[n] = (((unsigned)key[2*n]) << 8) | key[2*n+1];
    }

    for (n = 0; n < 8; n++) {
	Kprime[n] = ukey[n] ^ C[n];
    }

    for(n = 0; n < 8; n++) {
	cs->kasumi.KLi1[n] = ROL16(ukey[n],1);
	cs->kasumi.KLi2[n] = Kprime[(n+2)&0x7];
	cs->kasumi.KOi1[n] = ROL16(ukey[(n+1)&0x7],5);
	cs->kasumi.KOi2[n] = ROL16(ukey[(n+5)&0x7],8);
	cs->kasumi.KOi3[n] = ROL16(ukey[(n+6)&0x7],13);
	cs->kasumi.KIi1[n] = Kprime[(n+4)&0x7];
	cs->kasumi.KIi2[n] = Kprime[(n+3)&0x7];
	cs->kasumi.KIi3[n] = Kprime[(n+7)&0x7];
    }

    return NBSCrypto_OK;
}

int kasumi_encrypt(const unsigned char *pt, unsigned char *ct, const cipher_state *cs)
{
    unsigned left, right, temp;
    int n;

    LOAD32(left, pt);
    LOAD32(right, pt+4);

    for (n = 0; n <= 7; ) {
	temp = _FL(left,  n,   cs);
	temp = _FO(temp,  n++, cs);
	right ^= temp;
	temp = _FO(right, n,   cs);
	temp = _FL(temp,  n++, cs);
	left ^= temp;
    }

    STORE32(left, ct);
    STORE32(right, ct+4);

    return NBSCrypto_OK;
}

int kasumi_decrypt(const unsigned char *ct, unsigned char *pt, const cipher_state *cs)
{
    unsigned left, right, temp;
    int n;

    LOAD32(left, ct);
    LOAD32(right, ct+4);

    for (n = 7; n >= 0; ) {
	temp = _FO(right, n,   cs);
	temp = _FL(temp,  n--, cs);
	left ^= temp;
	temp = _FL(left,  n,   cs);
	temp = _FO(temp,  n--, cs);
	right ^= temp;
    }

    STORE32(left, pt);
    STORE32(right, pt+4);

    return NBSCrypto_OK;
}

void kasumi_done(cipher_state *cs)
{
    zeromem(cs, sizeof(cs->kasumi));
}
