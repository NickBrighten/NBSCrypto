//
//	ripemd.c
//	Authors / Developers		: Hans Dobbertin, Antoon Bosselaers, Bart Preneel
//	Last Modified (Original)	: 1996 (1992)
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor ripemd_128_desc =
{
    "ripemd-128",
    180,
    16,
    64,
    &ripemd_128_init,
    &ripemd_128_process,
    &ripemd_128_done,
    NULL
};

const struct hash_descriptor ripemd_160_desc =
{
    "ripemd-160",
    181,
    20,
    64,
    &ripemd_160_init,
    &ripemd_160_process,
    &ripemd_160_done,
    NULL
};

const struct hash_descriptor ripemd_256_desc =
{
    "ripemd-256",
    182,
    32,
    64,
    &ripemd_256_init,
    &ripemd_256_process,
    &ripemd_256_done,
    NULL
};

const struct hash_descriptor ripemd_320_desc =
{
    "ripemd-320",
    183,
    40,
    64,
    &ripemd_320_init,
    &ripemd_320_process,
    &ripemd_320_done,
    NULL
};




#pragma mark - DEFINES
#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z) (((x) | ~(y)) ^ (z))
#define I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z) ((x) ^ ((y) | ~(z)))

#define FF128(a, b, c, d, x, s)				\
    (a) += F((b), (c), (d)) + (x);			\
    (a) = ROLc((a), (s));

#define FF160(a, b, c, d, e, x, s)			\
    (a) += F((b), (c), (d)) + (x);			\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define GG128(a, b, c, d, x, s)				\
    (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;	\
    (a) = ROLc((a), (s));

#define GG160(a, b, c, d, e, x, s)			\
    (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;	\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define HH128(a, b, c, d, x, s)				\
    (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;	\
    (a) = ROLc((a), (s));

#define HH160(a, b, c, d, e, x, s)			\
    (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;	\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define II128(a, b, c, d, x, s)				\
    (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;	\
    (a) = ROLc((a), (s));

#define II160(a, b, c, d, e, x, s)			\
    (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;	\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define JJ160(a, b, c, d, e, x, s)			\
    (a) += J((b), (c), (d)) + (x) + 0xa953fd4eUL;	\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define FFF128(a, b, c, d, x, s)			\
    (a) += F((b), (c), (d)) + (x);			\
    (a) = ROLc((a), (s));

#define FFF160(a, b, c, d, e, x, s)			\
    (a) += F((b), (c), (d)) + (x);			\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define GGG128(a, b, c, d, x, s)			\
    (a) += G((b), (c), (d)) + (x) + 0x6d703ef3UL;	\
    (a) = ROLc((a), (s));

#define GGG160(a, b, c, d, e, x, s)			\
    (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9UL;	\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define HHH128(a, b, c, d, x, s)			\
    (a) += H((b), (c), (d)) + (x) + 0x5c4dd124UL;	\
    (a) = ROLc((a), (s));

#define HHH160(a, b, c, d, e, x, s)			\
    (a) += H((b), (c), (d)) + (x) + 0x6d703ef3UL;	\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define III128(a, b, c, d, x, s)			\
    (a) += I((b), (c), (d)) + (x) + 0x50a28be6UL;	\
    (a) = ROLc((a), (s));

#define III160(a, b, c, d, e, x, s)			\
    (a) += I((b), (c), (d)) + (x) + 0x5c4dd124UL;	\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define JJJ160(a, b, c, d, e, x, s)			\
    (a) += J((b), (c), (d)) + (x) + 0x50a28be6UL;	\
    (a) = ROLc((a), (s)) + (e);				\
    (c) = ROLc((c), 10);

#define STORE32L(x, y)										\
    do {											\
	(y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);	\
	(y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255);		\
    } while(0)

#define LOAD32L(x, y)										\
    do {x = ((unsigned)((y)[3] & 255)<<24) | ((unsigned)((y)[2] & 255)<<16) |			\
	((unsigned)((y)[1] & 255)<<8)  | ((unsigned)((y)[0] & 255));				\
    } while(0)

#define STORE64L(x,y)										\
    do {(y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);	\
	(y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);	\
	(y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);	\
	(y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255);		\
    } while(0)

#define ROLc(x, y) ((((unsigned)(x)<<(unsigned)((y)&31)) | (((unsigned)(x)&0xFFFFFFFF)>>(unsigned)((32-((y)&31))&31))) & 0xFFFFFFFF)

#define MIN(x, y) (((x)<(y))?(x):(y))




#pragma mark - INLINE
static inline int _ripemd_128_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned aa,bb,cc,dd,aaa,bbb,ccc,ddd,X[16];
    int i;

    for (i = 0; i < 16; i++){
	LOAD32L(X[i], buf + (4 * i));
    }


    aa = aaa = hs->ripemd128.state[0];
    bb = bbb = hs->ripemd128.state[1];
    cc = ccc = hs->ripemd128.state[2];
    dd = ddd = hs->ripemd128.state[3];

    /* round 1 */
    FF128(aa, bb, cc, dd, X[ 0], 11);
    FF128(dd, aa, bb, cc, X[ 1], 14);
    FF128(cc, dd, aa, bb, X[ 2], 15);
    FF128(bb, cc, dd, aa, X[ 3], 12);
    FF128(aa, bb, cc, dd, X[ 4],  5);
    FF128(dd, aa, bb, cc, X[ 5],  8);
    FF128(cc, dd, aa, bb, X[ 6],  7);
    FF128(bb, cc, dd, aa, X[ 7],  9);
    FF128(aa, bb, cc, dd, X[ 8], 11);
    FF128(dd, aa, bb, cc, X[ 9], 13);
    FF128(cc, dd, aa, bb, X[10], 14);
    FF128(bb, cc, dd, aa, X[11], 15);
    FF128(aa, bb, cc, dd, X[12],  6);
    FF128(dd, aa, bb, cc, X[13],  7);
    FF128(cc, dd, aa, bb, X[14],  9);
    FF128(bb, cc, dd, aa, X[15],  8);

    /* round 2 */
    GG128(aa, bb, cc, dd, X[ 7],  7);
    GG128(dd, aa, bb, cc, X[ 4],  6);
    GG128(cc, dd, aa, bb, X[13],  8);
    GG128(bb, cc, dd, aa, X[ 1], 13);
    GG128(aa, bb, cc, dd, X[10], 11);
    GG128(dd, aa, bb, cc, X[ 6],  9);
    GG128(cc, dd, aa, bb, X[15],  7);
    GG128(bb, cc, dd, aa, X[ 3], 15);
    GG128(aa, bb, cc, dd, X[12],  7);
    GG128(dd, aa, bb, cc, X[ 0], 12);
    GG128(cc, dd, aa, bb, X[ 9], 15);
    GG128(bb, cc, dd, aa, X[ 5],  9);
    GG128(aa, bb, cc, dd, X[ 2], 11);
    GG128(dd, aa, bb, cc, X[14],  7);
    GG128(cc, dd, aa, bb, X[11], 13);
    GG128(bb, cc, dd, aa, X[ 8], 12);

    /* round 3 */
    HH128(aa, bb, cc, dd, X[ 3], 11);
    HH128(dd, aa, bb, cc, X[10], 13);
    HH128(cc, dd, aa, bb, X[14],  6);
    HH128(bb, cc, dd, aa, X[ 4],  7);
    HH128(aa, bb, cc, dd, X[ 9], 14);
    HH128(dd, aa, bb, cc, X[15],  9);
    HH128(cc, dd, aa, bb, X[ 8], 13);
    HH128(bb, cc, dd, aa, X[ 1], 15);
    HH128(aa, bb, cc, dd, X[ 2], 14);
    HH128(dd, aa, bb, cc, X[ 7],  8);
    HH128(cc, dd, aa, bb, X[ 0], 13);
    HH128(bb, cc, dd, aa, X[ 6],  6);
    HH128(aa, bb, cc, dd, X[13],  5);
    HH128(dd, aa, bb, cc, X[11], 12);
    HH128(cc, dd, aa, bb, X[ 5],  7);
    HH128(bb, cc, dd, aa, X[12],  5);

    /* round 4 */
    II128(aa, bb, cc, dd, X[ 1], 11);
    II128(dd, aa, bb, cc, X[ 9], 12);
    II128(cc, dd, aa, bb, X[11], 14);
    II128(bb, cc, dd, aa, X[10], 15);
    II128(aa, bb, cc, dd, X[ 0], 14);
    II128(dd, aa, bb, cc, X[ 8], 15);
    II128(cc, dd, aa, bb, X[12],  9);
    II128(bb, cc, dd, aa, X[ 4],  8);
    II128(aa, bb, cc, dd, X[13],  9);
    II128(dd, aa, bb, cc, X[ 3], 14);
    II128(cc, dd, aa, bb, X[ 7],  5);
    II128(bb, cc, dd, aa, X[15],  6);
    II128(aa, bb, cc, dd, X[14],  8);
    II128(dd, aa, bb, cc, X[ 5],  6);
    II128(cc, dd, aa, bb, X[ 6],  5);
    II128(bb, cc, dd, aa, X[ 2], 12);

    /* parallel round 1 */
    III128(aaa, bbb, ccc, ddd, X[ 5],  8);
    III128(ddd, aaa, bbb, ccc, X[14],  9);
    III128(ccc, ddd, aaa, bbb, X[ 7],  9);
    III128(bbb, ccc, ddd, aaa, X[ 0], 11);
    III128(aaa, bbb, ccc, ddd, X[ 9], 13);
    III128(ddd, aaa, bbb, ccc, X[ 2], 15);
    III128(ccc, ddd, aaa, bbb, X[11], 15);
    III128(bbb, ccc, ddd, aaa, X[ 4],  5);
    III128(aaa, bbb, ccc, ddd, X[13],  7);
    III128(ddd, aaa, bbb, ccc, X[ 6],  7);
    III128(ccc, ddd, aaa, bbb, X[15],  8);
    III128(bbb, ccc, ddd, aaa, X[ 8], 11);
    III128(aaa, bbb, ccc, ddd, X[ 1], 14);
    III128(ddd, aaa, bbb, ccc, X[10], 14);
    III128(ccc, ddd, aaa, bbb, X[ 3], 12);
    III128(bbb, ccc, ddd, aaa, X[12],  6);

    /* parallel round 2 */
    HHH128(aaa, bbb, ccc, ddd, X[ 6],  9);
    HHH128(ddd, aaa, bbb, ccc, X[11], 13);
    HHH128(ccc, ddd, aaa, bbb, X[ 3], 15);
    HHH128(bbb, ccc, ddd, aaa, X[ 7],  7);
    HHH128(aaa, bbb, ccc, ddd, X[ 0], 12);
    HHH128(ddd, aaa, bbb, ccc, X[13],  8);
    HHH128(ccc, ddd, aaa, bbb, X[ 5],  9);
    HHH128(bbb, ccc, ddd, aaa, X[10], 11);
    HHH128(aaa, bbb, ccc, ddd, X[14],  7);
    HHH128(ddd, aaa, bbb, ccc, X[15],  7);
    HHH128(ccc, ddd, aaa, bbb, X[ 8], 12);
    HHH128(bbb, ccc, ddd, aaa, X[12],  7);
    HHH128(aaa, bbb, ccc, ddd, X[ 4],  6);
    HHH128(ddd, aaa, bbb, ccc, X[ 9], 15);
    HHH128(ccc, ddd, aaa, bbb, X[ 1], 13);
    HHH128(bbb, ccc, ddd, aaa, X[ 2], 11);

    /* parallel round 3 */
    GGG128(aaa, bbb, ccc, ddd, X[15],  9);
    GGG128(ddd, aaa, bbb, ccc, X[ 5],  7);
    GGG128(ccc, ddd, aaa, bbb, X[ 1], 15);
    GGG128(bbb, ccc, ddd, aaa, X[ 3], 11);
    GGG128(aaa, bbb, ccc, ddd, X[ 7],  8);
    GGG128(ddd, aaa, bbb, ccc, X[14],  6);
    GGG128(ccc, ddd, aaa, bbb, X[ 6],  6);
    GGG128(bbb, ccc, ddd, aaa, X[ 9], 14);
    GGG128(aaa, bbb, ccc, ddd, X[11], 12);
    GGG128(ddd, aaa, bbb, ccc, X[ 8], 13);
    GGG128(ccc, ddd, aaa, bbb, X[12],  5);
    GGG128(bbb, ccc, ddd, aaa, X[ 2], 14);
    GGG128(aaa, bbb, ccc, ddd, X[10], 13);
    GGG128(ddd, aaa, bbb, ccc, X[ 0], 13);
    GGG128(ccc, ddd, aaa, bbb, X[ 4],  7);
    GGG128(bbb, ccc, ddd, aaa, X[13],  5);

    /* parallel round 4 */
    FFF128(aaa, bbb, ccc, ddd, X[ 8], 15);
    FFF128(ddd, aaa, bbb, ccc, X[ 6],  5);
    FFF128(ccc, ddd, aaa, bbb, X[ 4],  8);
    FFF128(bbb, ccc, ddd, aaa, X[ 1], 11);
    FFF128(aaa, bbb, ccc, ddd, X[ 3], 14);
    FFF128(ddd, aaa, bbb, ccc, X[11], 14);
    FFF128(ccc, ddd, aaa, bbb, X[15],  6);
    FFF128(bbb, ccc, ddd, aaa, X[ 0], 14);
    FFF128(aaa, bbb, ccc, ddd, X[ 5],  6);
    FFF128(ddd, aaa, bbb, ccc, X[12],  9);
    FFF128(ccc, ddd, aaa, bbb, X[ 2], 12);
    FFF128(bbb, ccc, ddd, aaa, X[13],  9);
    FFF128(aaa, bbb, ccc, ddd, X[ 9], 12);
    FFF128(ddd, aaa, bbb, ccc, X[ 7],  5);
    FFF128(ccc, ddd, aaa, bbb, X[10], 15);
    FFF128(bbb, ccc, ddd, aaa, X[14],  8);

    ddd += cc + hs->ripemd128.state[1];

    hs->ripemd128.state[1] = hs->ripemd128.state[2] + dd + aaa;
    hs->ripemd128.state[2] = hs->ripemd128.state[3] + aa + bbb;
    hs->ripemd128.state[3] = hs->ripemd128.state[0] + bb + ccc;
    hs->ripemd128.state[0] = ddd;

    return NBSCrypto_OK;
}

static inline int _ripemd_160_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned aa,bb,cc,dd,ee,aaa,bbb,ccc,ddd,eee,X[16];
    int i;

    for (i = 0; i < 16; i++){
	LOAD32L(X[i], buf + (4 * i));
    }

    aa = aaa = hs->ripemd160.state[0];
    bb = bbb = hs->ripemd160.state[1];
    cc = ccc = hs->ripemd160.state[2];
    dd = ddd = hs->ripemd160.state[3];
    ee = eee = hs->ripemd160.state[4];

    /* round 1 */
    FF160(aa, bb, cc, dd, ee, X[ 0], 11);
    FF160(ee, aa, bb, cc, dd, X[ 1], 14);
    FF160(dd, ee, aa, bb, cc, X[ 2], 15);
    FF160(cc, dd, ee, aa, bb, X[ 3], 12);
    FF160(bb, cc, dd, ee, aa, X[ 4],  5);
    FF160(aa, bb, cc, dd, ee, X[ 5],  8);
    FF160(ee, aa, bb, cc, dd, X[ 6],  7);
    FF160(dd, ee, aa, bb, cc, X[ 7],  9);
    FF160(cc, dd, ee, aa, bb, X[ 8], 11);
    FF160(bb, cc, dd, ee, aa, X[ 9], 13);
    FF160(aa, bb, cc, dd, ee, X[10], 14);
    FF160(ee, aa, bb, cc, dd, X[11], 15);
    FF160(dd, ee, aa, bb, cc, X[12],  6);
    FF160(cc, dd, ee, aa, bb, X[13],  7);
    FF160(bb, cc, dd, ee, aa, X[14],  9);
    FF160(aa, bb, cc, dd, ee, X[15],  8);

    /* round 2 */
    GG160(ee, aa, bb, cc, dd, X[ 7],  7);
    GG160(dd, ee, aa, bb, cc, X[ 4],  6);
    GG160(cc, dd, ee, aa, bb, X[13],  8);
    GG160(bb, cc, dd, ee, aa, X[ 1], 13);
    GG160(aa, bb, cc, dd, ee, X[10], 11);
    GG160(ee, aa, bb, cc, dd, X[ 6],  9);
    GG160(dd, ee, aa, bb, cc, X[15],  7);
    GG160(cc, dd, ee, aa, bb, X[ 3], 15);
    GG160(bb, cc, dd, ee, aa, X[12],  7);
    GG160(aa, bb, cc, dd, ee, X[ 0], 12);
    GG160(ee, aa, bb, cc, dd, X[ 9], 15);
    GG160(dd, ee, aa, bb, cc, X[ 5],  9);
    GG160(cc, dd, ee, aa, bb, X[ 2], 11);
    GG160(bb, cc, dd, ee, aa, X[14],  7);
    GG160(aa, bb, cc, dd, ee, X[11], 13);
    GG160(ee, aa, bb, cc, dd, X[ 8], 12);

    /* round 3 */
    HH160(dd, ee, aa, bb, cc, X[ 3], 11);
    HH160(cc, dd, ee, aa, bb, X[10], 13);
    HH160(bb, cc, dd, ee, aa, X[14],  6);
    HH160(aa, bb, cc, dd, ee, X[ 4],  7);
    HH160(ee, aa, bb, cc, dd, X[ 9], 14);
    HH160(dd, ee, aa, bb, cc, X[15],  9);
    HH160(cc, dd, ee, aa, bb, X[ 8], 13);
    HH160(bb, cc, dd, ee, aa, X[ 1], 15);
    HH160(aa, bb, cc, dd, ee, X[ 2], 14);
    HH160(ee, aa, bb, cc, dd, X[ 7],  8);
    HH160(dd, ee, aa, bb, cc, X[ 0], 13);
    HH160(cc, dd, ee, aa, bb, X[ 6],  6);
    HH160(bb, cc, dd, ee, aa, X[13],  5);
    HH160(aa, bb, cc, dd, ee, X[11], 12);
    HH160(ee, aa, bb, cc, dd, X[ 5],  7);
    HH160(dd, ee, aa, bb, cc, X[12],  5);

    /* round 4 */
    II160(cc, dd, ee, aa, bb, X[ 1], 11);
    II160(bb, cc, dd, ee, aa, X[ 9], 12);
    II160(aa, bb, cc, dd, ee, X[11], 14);
    II160(ee, aa, bb, cc, dd, X[10], 15);
    II160(dd, ee, aa, bb, cc, X[ 0], 14);
    II160(cc, dd, ee, aa, bb, X[ 8], 15);
    II160(bb, cc, dd, ee, aa, X[12],  9);
    II160(aa, bb, cc, dd, ee, X[ 4],  8);
    II160(ee, aa, bb, cc, dd, X[13],  9);
    II160(dd, ee, aa, bb, cc, X[ 3], 14);
    II160(cc, dd, ee, aa, bb, X[ 7],  5);
    II160(bb, cc, dd, ee, aa, X[15],  6);
    II160(aa, bb, cc, dd, ee, X[14],  8);
    II160(ee, aa, bb, cc, dd, X[ 5],  6);
    II160(dd, ee, aa, bb, cc, X[ 6],  5);
    II160(cc, dd, ee, aa, bb, X[ 2], 12);

    /* round 5 */
    JJ160(bb, cc, dd, ee, aa, X[ 4],  9);
    JJ160(aa, bb, cc, dd, ee, X[ 0], 15);
    JJ160(ee, aa, bb, cc, dd, X[ 5],  5);
    JJ160(dd, ee, aa, bb, cc, X[ 9], 11);
    JJ160(cc, dd, ee, aa, bb, X[ 7],  6);
    JJ160(bb, cc, dd, ee, aa, X[12],  8);
    JJ160(aa, bb, cc, dd, ee, X[ 2], 13);
    JJ160(ee, aa, bb, cc, dd, X[10], 12);
    JJ160(dd, ee, aa, bb, cc, X[14],  5);
    JJ160(cc, dd, ee, aa, bb, X[ 1], 12);
    JJ160(bb, cc, dd, ee, aa, X[ 3], 13);
    JJ160(aa, bb, cc, dd, ee, X[ 8], 14);
    JJ160(ee, aa, bb, cc, dd, X[11], 11);
    JJ160(dd, ee, aa, bb, cc, X[ 6],  8);
    JJ160(cc, dd, ee, aa, bb, X[15],  5);
    JJ160(bb, cc, dd, ee, aa, X[13],  6);

    /* parallel round 1 */
    JJJ160(aaa, bbb, ccc, ddd, eee, X[ 5],  8);
    JJJ160(eee, aaa, bbb, ccc, ddd, X[14],  9);
    JJJ160(ddd, eee, aaa, bbb, ccc, X[ 7],  9);
    JJJ160(ccc, ddd, eee, aaa, bbb, X[ 0], 11);
    JJJ160(bbb, ccc, ddd, eee, aaa, X[ 9], 13);
    JJJ160(aaa, bbb, ccc, ddd, eee, X[ 2], 15);
    JJJ160(eee, aaa, bbb, ccc, ddd, X[11], 15);
    JJJ160(ddd, eee, aaa, bbb, ccc, X[ 4],  5);
    JJJ160(ccc, ddd, eee, aaa, bbb, X[13],  7);
    JJJ160(bbb, ccc, ddd, eee, aaa, X[ 6],  7);
    JJJ160(aaa, bbb, ccc, ddd, eee, X[15],  8);
    JJJ160(eee, aaa, bbb, ccc, ddd, X[ 8], 11);
    JJJ160(ddd, eee, aaa, bbb, ccc, X[ 1], 14);
    JJJ160(ccc, ddd, eee, aaa, bbb, X[10], 14);
    JJJ160(bbb, ccc, ddd, eee, aaa, X[ 3], 12);
    JJJ160(aaa, bbb, ccc, ddd, eee, X[12],  6);

    /* parallel round 2 */
    III160(eee, aaa, bbb, ccc, ddd, X[ 6],  9);
    III160(ddd, eee, aaa, bbb, ccc, X[11], 13);
    III160(ccc, ddd, eee, aaa, bbb, X[ 3], 15);
    III160(bbb, ccc, ddd, eee, aaa, X[ 7],  7);
    III160(aaa, bbb, ccc, ddd, eee, X[ 0], 12);
    III160(eee, aaa, bbb, ccc, ddd, X[13],  8);
    III160(ddd, eee, aaa, bbb, ccc, X[ 5],  9);
    III160(ccc, ddd, eee, aaa, bbb, X[10], 11);
    III160(bbb, ccc, ddd, eee, aaa, X[14],  7);
    III160(aaa, bbb, ccc, ddd, eee, X[15],  7);
    III160(eee, aaa, bbb, ccc, ddd, X[ 8], 12);
    III160(ddd, eee, aaa, bbb, ccc, X[12],  7);
    III160(ccc, ddd, eee, aaa, bbb, X[ 4],  6);
    III160(bbb, ccc, ddd, eee, aaa, X[ 9], 15);
    III160(aaa, bbb, ccc, ddd, eee, X[ 1], 13);
    III160(eee, aaa, bbb, ccc, ddd, X[ 2], 11);

    /* parallel round 3 */
    HHH160(ddd, eee, aaa, bbb, ccc, X[15],  9);
    HHH160(ccc, ddd, eee, aaa, bbb, X[ 5],  7);
    HHH160(bbb, ccc, ddd, eee, aaa, X[ 1], 15);
    HHH160(aaa, bbb, ccc, ddd, eee, X[ 3], 11);
    HHH160(eee, aaa, bbb, ccc, ddd, X[ 7],  8);
    HHH160(ddd, eee, aaa, bbb, ccc, X[14],  6);
    HHH160(ccc, ddd, eee, aaa, bbb, X[ 6],  6);
    HHH160(bbb, ccc, ddd, eee, aaa, X[ 9], 14);
    HHH160(aaa, bbb, ccc, ddd, eee, X[11], 12);
    HHH160(eee, aaa, bbb, ccc, ddd, X[ 8], 13);
    HHH160(ddd, eee, aaa, bbb, ccc, X[12],  5);
    HHH160(ccc, ddd, eee, aaa, bbb, X[ 2], 14);
    HHH160(bbb, ccc, ddd, eee, aaa, X[10], 13);
    HHH160(aaa, bbb, ccc, ddd, eee, X[ 0], 13);
    HHH160(eee, aaa, bbb, ccc, ddd, X[ 4],  7);
    HHH160(ddd, eee, aaa, bbb, ccc, X[13],  5);

    /* parallel round 4 */
    GGG160(ccc, ddd, eee, aaa, bbb, X[ 8], 15);
    GGG160(bbb, ccc, ddd, eee, aaa, X[ 6],  5);
    GGG160(aaa, bbb, ccc, ddd, eee, X[ 4],  8);
    GGG160(eee, aaa, bbb, ccc, ddd, X[ 1], 11);
    GGG160(ddd, eee, aaa, bbb, ccc, X[ 3], 14);
    GGG160(ccc, ddd, eee, aaa, bbb, X[11], 14);
    GGG160(bbb, ccc, ddd, eee, aaa, X[15],  6);
    GGG160(aaa, bbb, ccc, ddd, eee, X[ 0], 14);
    GGG160(eee, aaa, bbb, ccc, ddd, X[ 5],  6);
    GGG160(ddd, eee, aaa, bbb, ccc, X[12],  9);
    GGG160(ccc, ddd, eee, aaa, bbb, X[ 2], 12);
    GGG160(bbb, ccc, ddd, eee, aaa, X[13],  9);
    GGG160(aaa, bbb, ccc, ddd, eee, X[ 9], 12);
    GGG160(eee, aaa, bbb, ccc, ddd, X[ 7],  5);
    GGG160(ddd, eee, aaa, bbb, ccc, X[10], 15);
    GGG160(ccc, ddd, eee, aaa, bbb, X[14],  8);

    /* parallel round 5 */
    FFF160(bbb, ccc, ddd, eee, aaa, X[12],  8);
    FFF160(aaa, bbb, ccc, ddd, eee, X[15],  5);
    FFF160(eee, aaa, bbb, ccc, ddd, X[10], 12);
    FFF160(ddd, eee, aaa, bbb, ccc, X[ 4],  9);
    FFF160(ccc, ddd, eee, aaa, bbb, X[ 1], 12);
    FFF160(bbb, ccc, ddd, eee, aaa, X[ 5],  5);
    FFF160(aaa, bbb, ccc, ddd, eee, X[ 8], 14);
    FFF160(eee, aaa, bbb, ccc, ddd, X[ 7],  6);
    FFF160(ddd, eee, aaa, bbb, ccc, X[ 6],  8);
    FFF160(ccc, ddd, eee, aaa, bbb, X[ 2], 13);
    FFF160(bbb, ccc, ddd, eee, aaa, X[13],  6);
    FFF160(aaa, bbb, ccc, ddd, eee, X[14],  5);
    FFF160(eee, aaa, bbb, ccc, ddd, X[ 0], 15);
    FFF160(ddd, eee, aaa, bbb, ccc, X[ 3], 13);
    FFF160(ccc, ddd, eee, aaa, bbb, X[ 9], 11);
    FFF160(bbb, ccc, ddd, eee, aaa, X[11], 11);

    ddd += cc + hs->ripemd160.state[1];

    hs->ripemd160.state[1] = hs->ripemd160.state[2] + dd + eee;
    hs->ripemd160.state[2] = hs->ripemd160.state[3] + ee + aaa;
    hs->ripemd160.state[3] = hs->ripemd160.state[4] + aa + bbb;
    hs->ripemd160.state[4] = hs->ripemd160.state[0] + bb + ccc;
    hs->ripemd160.state[0] = ddd;

    return NBSCrypto_OK;
}

static inline int _ripemd_256_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned aa,bb,cc,dd,aaa,bbb,ccc,ddd,tmp,X[16];
    int i;

    for (i = 0; i < 16; i++){
	LOAD32L(X[i], buf + (4 * i));
    }

    aa  = hs->ripemd256.state[0];
    bb  = hs->ripemd256.state[1];
    cc  = hs->ripemd256.state[2];
    dd  = hs->ripemd256.state[3];
    aaa = hs->ripemd256.state[4];
    bbb = hs->ripemd256.state[5];
    ccc = hs->ripemd256.state[6];
    ddd = hs->ripemd256.state[7];

    /* round 1 */
    FF128(aa, bb, cc, dd, X[ 0], 11);
    FF128(dd, aa, bb, cc, X[ 1], 14);
    FF128(cc, dd, aa, bb, X[ 2], 15);
    FF128(bb, cc, dd, aa, X[ 3], 12);
    FF128(aa, bb, cc, dd, X[ 4],  5);
    FF128(dd, aa, bb, cc, X[ 5],  8);
    FF128(cc, dd, aa, bb, X[ 6],  7);
    FF128(bb, cc, dd, aa, X[ 7],  9);
    FF128(aa, bb, cc, dd, X[ 8], 11);
    FF128(dd, aa, bb, cc, X[ 9], 13);
    FF128(cc, dd, aa, bb, X[10], 14);
    FF128(bb, cc, dd, aa, X[11], 15);
    FF128(aa, bb, cc, dd, X[12],  6);
    FF128(dd, aa, bb, cc, X[13],  7);
    FF128(cc, dd, aa, bb, X[14],  9);
    FF128(bb, cc, dd, aa, X[15],  8);

    /* parallel round 1 */
    III128(aaa, bbb, ccc, ddd, X[ 5],  8);
    III128(ddd, aaa, bbb, ccc, X[14],  9);
    III128(ccc, ddd, aaa, bbb, X[ 7],  9);
    III128(bbb, ccc, ddd, aaa, X[ 0], 11);
    III128(aaa, bbb, ccc, ddd, X[ 9], 13);
    III128(ddd, aaa, bbb, ccc, X[ 2], 15);
    III128(ccc, ddd, aaa, bbb, X[11], 15);
    III128(bbb, ccc, ddd, aaa, X[ 4],  5);
    III128(aaa, bbb, ccc, ddd, X[13],  7);
    III128(ddd, aaa, bbb, ccc, X[ 6],  7);
    III128(ccc, ddd, aaa, bbb, X[15],  8);
    III128(bbb, ccc, ddd, aaa, X[ 8], 11);
    III128(aaa, bbb, ccc, ddd, X[ 1], 14);
    III128(ddd, aaa, bbb, ccc, X[10], 14);
    III128(ccc, ddd, aaa, bbb, X[ 3], 12);
    III128(bbb, ccc, ddd, aaa, X[12],  6);

    tmp = aa; aa = aaa; aaa = tmp;

    /* round 2 */
    GG128(aa, bb, cc, dd, X[ 7],  7);
    GG128(dd, aa, bb, cc, X[ 4],  6);
    GG128(cc, dd, aa, bb, X[13],  8);
    GG128(bb, cc, dd, aa, X[ 1], 13);
    GG128(aa, bb, cc, dd, X[10], 11);
    GG128(dd, aa, bb, cc, X[ 6],  9);
    GG128(cc, dd, aa, bb, X[15],  7);
    GG128(bb, cc, dd, aa, X[ 3], 15);
    GG128(aa, bb, cc, dd, X[12],  7);
    GG128(dd, aa, bb, cc, X[ 0], 12);
    GG128(cc, dd, aa, bb, X[ 9], 15);
    GG128(bb, cc, dd, aa, X[ 5],  9);
    GG128(aa, bb, cc, dd, X[ 2], 11);
    GG128(dd, aa, bb, cc, X[14],  7);
    GG128(cc, dd, aa, bb, X[11], 13);
    GG128(bb, cc, dd, aa, X[ 8], 12);

    /* parallel round 2 */
    HHH128(aaa, bbb, ccc, ddd, X[ 6],  9);
    HHH128(ddd, aaa, bbb, ccc, X[11], 13);
    HHH128(ccc, ddd, aaa, bbb, X[ 3], 15);
    HHH128(bbb, ccc, ddd, aaa, X[ 7],  7);
    HHH128(aaa, bbb, ccc, ddd, X[ 0], 12);
    HHH128(ddd, aaa, bbb, ccc, X[13],  8);
    HHH128(ccc, ddd, aaa, bbb, X[ 5],  9);
    HHH128(bbb, ccc, ddd, aaa, X[10], 11);
    HHH128(aaa, bbb, ccc, ddd, X[14],  7);
    HHH128(ddd, aaa, bbb, ccc, X[15],  7);
    HHH128(ccc, ddd, aaa, bbb, X[ 8], 12);
    HHH128(bbb, ccc, ddd, aaa, X[12],  7);
    HHH128(aaa, bbb, ccc, ddd, X[ 4],  6);
    HHH128(ddd, aaa, bbb, ccc, X[ 9], 15);
    HHH128(ccc, ddd, aaa, bbb, X[ 1], 13);
    HHH128(bbb, ccc, ddd, aaa, X[ 2], 11);

    tmp = bb; bb = bbb; bbb = tmp;

    /* round 3 */
    HH128(aa, bb, cc, dd, X[ 3], 11);
    HH128(dd, aa, bb, cc, X[10], 13);
    HH128(cc, dd, aa, bb, X[14],  6);
    HH128(bb, cc, dd, aa, X[ 4],  7);
    HH128(aa, bb, cc, dd, X[ 9], 14);
    HH128(dd, aa, bb, cc, X[15],  9);
    HH128(cc, dd, aa, bb, X[ 8], 13);
    HH128(bb, cc, dd, aa, X[ 1], 15);
    HH128(aa, bb, cc, dd, X[ 2], 14);
    HH128(dd, aa, bb, cc, X[ 7],  8);
    HH128(cc, dd, aa, bb, X[ 0], 13);
    HH128(bb, cc, dd, aa, X[ 6],  6);
    HH128(aa, bb, cc, dd, X[13],  5);
    HH128(dd, aa, bb, cc, X[11], 12);
    HH128(cc, dd, aa, bb, X[ 5],  7);
    HH128(bb, cc, dd, aa, X[12],  5);

    /* parallel round 3 */
    GGG128(aaa, bbb, ccc, ddd, X[15],  9);
    GGG128(ddd, aaa, bbb, ccc, X[ 5],  7);
    GGG128(ccc, ddd, aaa, bbb, X[ 1], 15);
    GGG128(bbb, ccc, ddd, aaa, X[ 3], 11);
    GGG128(aaa, bbb, ccc, ddd, X[ 7],  8);
    GGG128(ddd, aaa, bbb, ccc, X[14],  6);
    GGG128(ccc, ddd, aaa, bbb, X[ 6],  6);
    GGG128(bbb, ccc, ddd, aaa, X[ 9], 14);
    GGG128(aaa, bbb, ccc, ddd, X[11], 12);
    GGG128(ddd, aaa, bbb, ccc, X[ 8], 13);
    GGG128(ccc, ddd, aaa, bbb, X[12],  5);
    GGG128(bbb, ccc, ddd, aaa, X[ 2], 14);
    GGG128(aaa, bbb, ccc, ddd, X[10], 13);
    GGG128(ddd, aaa, bbb, ccc, X[ 0], 13);
    GGG128(ccc, ddd, aaa, bbb, X[ 4],  7);
    GGG128(bbb, ccc, ddd, aaa, X[13],  5);

    tmp = cc; cc = ccc; ccc = tmp;

    /* round 4 */
    II128(aa, bb, cc, dd, X[ 1], 11);
    II128(dd, aa, bb, cc, X[ 9], 12);
    II128(cc, dd, aa, bb, X[11], 14);
    II128(bb, cc, dd, aa, X[10], 15);
    II128(aa, bb, cc, dd, X[ 0], 14);
    II128(dd, aa, bb, cc, X[ 8], 15);
    II128(cc, dd, aa, bb, X[12],  9);
    II128(bb, cc, dd, aa, X[ 4],  8);
    II128(aa, bb, cc, dd, X[13],  9);
    II128(dd, aa, bb, cc, X[ 3], 14);
    II128(cc, dd, aa, bb, X[ 7],  5);
    II128(bb, cc, dd, aa, X[15],  6);
    II128(aa, bb, cc, dd, X[14],  8);
    II128(dd, aa, bb, cc, X[ 5],  6);
    II128(cc, dd, aa, bb, X[ 6],  5);
    II128(bb, cc, dd, aa, X[ 2], 12);

    /* parallel round 4 */
    FFF128(aaa, bbb, ccc, ddd, X[ 8], 15);
    FFF128(ddd, aaa, bbb, ccc, X[ 6],  5);
    FFF128(ccc, ddd, aaa, bbb, X[ 4],  8);
    FFF128(bbb, ccc, ddd, aaa, X[ 1], 11);
    FFF128(aaa, bbb, ccc, ddd, X[ 3], 14);
    FFF128(ddd, aaa, bbb, ccc, X[11], 14);
    FFF128(ccc, ddd, aaa, bbb, X[15],  6);
    FFF128(bbb, ccc, ddd, aaa, X[ 0], 14);
    FFF128(aaa, bbb, ccc, ddd, X[ 5],  6);
    FFF128(ddd, aaa, bbb, ccc, X[12],  9);
    FFF128(ccc, ddd, aaa, bbb, X[ 2], 12);
    FFF128(bbb, ccc, ddd, aaa, X[13],  9);
    FFF128(aaa, bbb, ccc, ddd, X[ 9], 12);
    FFF128(ddd, aaa, bbb, ccc, X[ 7],  5);
    FFF128(ccc, ddd, aaa, bbb, X[10], 15);
    FFF128(bbb, ccc, ddd, aaa, X[14],  8);

    tmp = dd; dd = ddd; ddd = tmp;

    hs->ripemd256.state[0] += aa;
    hs->ripemd256.state[1] += bb;
    hs->ripemd256.state[2] += cc;
    hs->ripemd256.state[3] += dd;
    hs->ripemd256.state[4] += aaa;
    hs->ripemd256.state[5] += bbb;
    hs->ripemd256.state[6] += ccc;
    hs->ripemd256.state[7] += ddd;

    return NBSCrypto_OK;
}

static inline int _ripemd_320_compress(hash_state *hs, const unsigned char *buf)
{
    unsigned aa,bb,cc,dd,ee,aaa,bbb,ccc,ddd,eee,tmp,X[16];
    int i;

    for (i = 0; i < 16; i++){
	LOAD32L(X[i], buf + (4 * i));
    }

    aa  = hs->ripemd320.state[0];
    bb  = hs->ripemd320.state[1];
    cc  = hs->ripemd320.state[2];
    dd  = hs->ripemd320.state[3];
    ee  = hs->ripemd320.state[4];
    aaa = hs->ripemd320.state[5];
    bbb = hs->ripemd320.state[6];
    ccc = hs->ripemd320.state[7];
    ddd = hs->ripemd320.state[8];
    eee = hs->ripemd320.state[9];

    /* round 1 */
    FF160(aa, bb, cc, dd, ee, X[ 0], 11);
    FF160(ee, aa, bb, cc, dd, X[ 1], 14);
    FF160(dd, ee, aa, bb, cc, X[ 2], 15);
    FF160(cc, dd, ee, aa, bb, X[ 3], 12);
    FF160(bb, cc, dd, ee, aa, X[ 4],  5);
    FF160(aa, bb, cc, dd, ee, X[ 5],  8);
    FF160(ee, aa, bb, cc, dd, X[ 6],  7);
    FF160(dd, ee, aa, bb, cc, X[ 7],  9);
    FF160(cc, dd, ee, aa, bb, X[ 8], 11);
    FF160(bb, cc, dd, ee, aa, X[ 9], 13);
    FF160(aa, bb, cc, dd, ee, X[10], 14);
    FF160(ee, aa, bb, cc, dd, X[11], 15);
    FF160(dd, ee, aa, bb, cc, X[12],  6);
    FF160(cc, dd, ee, aa, bb, X[13],  7);
    FF160(bb, cc, dd, ee, aa, X[14],  9);
    FF160(aa, bb, cc, dd, ee, X[15],  8);

    /* parallel round 1 */
    JJJ160(aaa, bbb, ccc, ddd, eee, X[ 5],  8);
    JJJ160(eee, aaa, bbb, ccc, ddd, X[14],  9);
    JJJ160(ddd, eee, aaa, bbb, ccc, X[ 7],  9);
    JJJ160(ccc, ddd, eee, aaa, bbb, X[ 0], 11);
    JJJ160(bbb, ccc, ddd, eee, aaa, X[ 9], 13);
    JJJ160(aaa, bbb, ccc, ddd, eee, X[ 2], 15);
    JJJ160(eee, aaa, bbb, ccc, ddd, X[11], 15);
    JJJ160(ddd, eee, aaa, bbb, ccc, X[ 4],  5);
    JJJ160(ccc, ddd, eee, aaa, bbb, X[13],  7);
    JJJ160(bbb, ccc, ddd, eee, aaa, X[ 6],  7);
    JJJ160(aaa, bbb, ccc, ddd, eee, X[15],  8);
    JJJ160(eee, aaa, bbb, ccc, ddd, X[ 8], 11);
    JJJ160(ddd, eee, aaa, bbb, ccc, X[ 1], 14);
    JJJ160(ccc, ddd, eee, aaa, bbb, X[10], 14);
    JJJ160(bbb, ccc, ddd, eee, aaa, X[ 3], 12);
    JJJ160(aaa, bbb, ccc, ddd, eee, X[12],  6);

    tmp = aa; aa = aaa; aaa = tmp;

    /* round 2 */
    GG160(ee, aa, bb, cc, dd, X[ 7],  7);
    GG160(dd, ee, aa, bb, cc, X[ 4],  6);
    GG160(cc, dd, ee, aa, bb, X[13],  8);
    GG160(bb, cc, dd, ee, aa, X[ 1], 13);
    GG160(aa, bb, cc, dd, ee, X[10], 11);
    GG160(ee, aa, bb, cc, dd, X[ 6],  9);
    GG160(dd, ee, aa, bb, cc, X[15],  7);
    GG160(cc, dd, ee, aa, bb, X[ 3], 15);
    GG160(bb, cc, dd, ee, aa, X[12],  7);
    GG160(aa, bb, cc, dd, ee, X[ 0], 12);
    GG160(ee, aa, bb, cc, dd, X[ 9], 15);
    GG160(dd, ee, aa, bb, cc, X[ 5],  9);
    GG160(cc, dd, ee, aa, bb, X[ 2], 11);
    GG160(bb, cc, dd, ee, aa, X[14],  7);
    GG160(aa, bb, cc, dd, ee, X[11], 13);
    GG160(ee, aa, bb, cc, dd, X[ 8], 12);

    /* parallel round 2 */
    III160(eee, aaa, bbb, ccc, ddd, X[ 6],  9);
    III160(ddd, eee, aaa, bbb, ccc, X[11], 13);
    III160(ccc, ddd, eee, aaa, bbb, X[ 3], 15);
    III160(bbb, ccc, ddd, eee, aaa, X[ 7],  7);
    III160(aaa, bbb, ccc, ddd, eee, X[ 0], 12);
    III160(eee, aaa, bbb, ccc, ddd, X[13],  8);
    III160(ddd, eee, aaa, bbb, ccc, X[ 5],  9);
    III160(ccc, ddd, eee, aaa, bbb, X[10], 11);
    III160(bbb, ccc, ddd, eee, aaa, X[14],  7);
    III160(aaa, bbb, ccc, ddd, eee, X[15],  7);
    III160(eee, aaa, bbb, ccc, ddd, X[ 8], 12);
    III160(ddd, eee, aaa, bbb, ccc, X[12],  7);
    III160(ccc, ddd, eee, aaa, bbb, X[ 4],  6);
    III160(bbb, ccc, ddd, eee, aaa, X[ 9], 15);
    III160(aaa, bbb, ccc, ddd, eee, X[ 1], 13);
    III160(eee, aaa, bbb, ccc, ddd, X[ 2], 11);

    tmp = bb; bb = bbb; bbb = tmp;

    /* round 3 */
    HH160(dd, ee, aa, bb, cc, X[ 3], 11);
    HH160(cc, dd, ee, aa, bb, X[10], 13);
    HH160(bb, cc, dd, ee, aa, X[14],  6);
    HH160(aa, bb, cc, dd, ee, X[ 4],  7);
    HH160(ee, aa, bb, cc, dd, X[ 9], 14);
    HH160(dd, ee, aa, bb, cc, X[15],  9);
    HH160(cc, dd, ee, aa, bb, X[ 8], 13);
    HH160(bb, cc, dd, ee, aa, X[ 1], 15);
    HH160(aa, bb, cc, dd, ee, X[ 2], 14);
    HH160(ee, aa, bb, cc, dd, X[ 7],  8);
    HH160(dd, ee, aa, bb, cc, X[ 0], 13);
    HH160(cc, dd, ee, aa, bb, X[ 6],  6);
    HH160(bb, cc, dd, ee, aa, X[13],  5);
    HH160(aa, bb, cc, dd, ee, X[11], 12);
    HH160(ee, aa, bb, cc, dd, X[ 5],  7);
    HH160(dd, ee, aa, bb, cc, X[12],  5);

    /* parallel round 3 */
    HHH160(ddd, eee, aaa, bbb, ccc, X[15],  9);
    HHH160(ccc, ddd, eee, aaa, bbb, X[ 5],  7);
    HHH160(bbb, ccc, ddd, eee, aaa, X[ 1], 15);
    HHH160(aaa, bbb, ccc, ddd, eee, X[ 3], 11);
    HHH160(eee, aaa, bbb, ccc, ddd, X[ 7],  8);
    HHH160(ddd, eee, aaa, bbb, ccc, X[14],  6);
    HHH160(ccc, ddd, eee, aaa, bbb, X[ 6],  6);
    HHH160(bbb, ccc, ddd, eee, aaa, X[ 9], 14);
    HHH160(aaa, bbb, ccc, ddd, eee, X[11], 12);
    HHH160(eee, aaa, bbb, ccc, ddd, X[ 8], 13);
    HHH160(ddd, eee, aaa, bbb, ccc, X[12],  5);
    HHH160(ccc, ddd, eee, aaa, bbb, X[ 2], 14);
    HHH160(bbb, ccc, ddd, eee, aaa, X[10], 13);
    HHH160(aaa, bbb, ccc, ddd, eee, X[ 0], 13);
    HHH160(eee, aaa, bbb, ccc, ddd, X[ 4],  7);
    HHH160(ddd, eee, aaa, bbb, ccc, X[13],  5);

    tmp = cc; cc = ccc; ccc = tmp;

    /* round 4 */
    II160(cc, dd, ee, aa, bb, X[ 1], 11);
    II160(bb, cc, dd, ee, aa, X[ 9], 12);
    II160(aa, bb, cc, dd, ee, X[11], 14);
    II160(ee, aa, bb, cc, dd, X[10], 15);
    II160(dd, ee, aa, bb, cc, X[ 0], 14);
    II160(cc, dd, ee, aa, bb, X[ 8], 15);
    II160(bb, cc, dd, ee, aa, X[12],  9);
    II160(aa, bb, cc, dd, ee, X[ 4],  8);
    II160(ee, aa, bb, cc, dd, X[13],  9);
    II160(dd, ee, aa, bb, cc, X[ 3], 14);
    II160(cc, dd, ee, aa, bb, X[ 7],  5);
    II160(bb, cc, dd, ee, aa, X[15],  6);
    II160(aa, bb, cc, dd, ee, X[14],  8);
    II160(ee, aa, bb, cc, dd, X[ 5],  6);
    II160(dd, ee, aa, bb, cc, X[ 6],  5);
    II160(cc, dd, ee, aa, bb, X[ 2], 12);

    /* parallel round 4 */
    GGG160(ccc, ddd, eee, aaa, bbb, X[ 8], 15);
    GGG160(bbb, ccc, ddd, eee, aaa, X[ 6],  5);
    GGG160(aaa, bbb, ccc, ddd, eee, X[ 4],  8);
    GGG160(eee, aaa, bbb, ccc, ddd, X[ 1], 11);
    GGG160(ddd, eee, aaa, bbb, ccc, X[ 3], 14);
    GGG160(ccc, ddd, eee, aaa, bbb, X[11], 14);
    GGG160(bbb, ccc, ddd, eee, aaa, X[15],  6);
    GGG160(aaa, bbb, ccc, ddd, eee, X[ 0], 14);
    GGG160(eee, aaa, bbb, ccc, ddd, X[ 5],  6);
    GGG160(ddd, eee, aaa, bbb, ccc, X[12],  9);
    GGG160(ccc, ddd, eee, aaa, bbb, X[ 2], 12);
    GGG160(bbb, ccc, ddd, eee, aaa, X[13],  9);
    GGG160(aaa, bbb, ccc, ddd, eee, X[ 9], 12);
    GGG160(eee, aaa, bbb, ccc, ddd, X[ 7],  5);
    GGG160(ddd, eee, aaa, bbb, ccc, X[10], 15);
    GGG160(ccc, ddd, eee, aaa, bbb, X[14],  8);

    tmp = dd; dd = ddd; ddd = tmp;

    /* round 5 */
    JJ160(bb, cc, dd, ee, aa, X[ 4],  9);
    JJ160(aa, bb, cc, dd, ee, X[ 0], 15);
    JJ160(ee, aa, bb, cc, dd, X[ 5],  5);
    JJ160(dd, ee, aa, bb, cc, X[ 9], 11);
    JJ160(cc, dd, ee, aa, bb, X[ 7],  6);
    JJ160(bb, cc, dd, ee, aa, X[12],  8);
    JJ160(aa, bb, cc, dd, ee, X[ 2], 13);
    JJ160(ee, aa, bb, cc, dd, X[10], 12);
    JJ160(dd, ee, aa, bb, cc, X[14],  5);
    JJ160(cc, dd, ee, aa, bb, X[ 1], 12);
    JJ160(bb, cc, dd, ee, aa, X[ 3], 13);
    JJ160(aa, bb, cc, dd, ee, X[ 8], 14);
    JJ160(ee, aa, bb, cc, dd, X[11], 11);
    JJ160(dd, ee, aa, bb, cc, X[ 6],  8);
    JJ160(cc, dd, ee, aa, bb, X[15],  5);
    JJ160(bb, cc, dd, ee, aa, X[13],  6);

    /* parallel round 5 */
    FFF160(bbb, ccc, ddd, eee, aaa, X[12],  8);
    FFF160(aaa, bbb, ccc, ddd, eee, X[15],  5);
    FFF160(eee, aaa, bbb, ccc, ddd, X[10], 12);
    FFF160(ddd, eee, aaa, bbb, ccc, X[ 4],  9);
    FFF160(ccc, ddd, eee, aaa, bbb, X[ 1], 12);
    FFF160(bbb, ccc, ddd, eee, aaa, X[ 5],  5);
    FFF160(aaa, bbb, ccc, ddd, eee, X[ 8], 14);
    FFF160(eee, aaa, bbb, ccc, ddd, X[ 7],  6);
    FFF160(ddd, eee, aaa, bbb, ccc, X[ 6],  8);
    FFF160(ccc, ddd, eee, aaa, bbb, X[ 2], 13);
    FFF160(bbb, ccc, ddd, eee, aaa, X[13],  6);
    FFF160(aaa, bbb, ccc, ddd, eee, X[14],  5);
    FFF160(eee, aaa, bbb, ccc, ddd, X[ 0], 15);
    FFF160(ddd, eee, aaa, bbb, ccc, X[ 3], 13);
    FFF160(ccc, ddd, eee, aaa, bbb, X[ 9], 11);
    FFF160(bbb, ccc, ddd, eee, aaa, X[11], 11);

    tmp = ee; ee = eee; eee = tmp;

    hs->ripemd320.state[0] += aa;
    hs->ripemd320.state[1] += bb;
    hs->ripemd320.state[2] += cc;
    hs->ripemd320.state[3] += dd;
    hs->ripemd320.state[4] += ee;
    hs->ripemd320.state[5] += aaa;
    hs->ripemd320.state[6] += bbb;
    hs->ripemd320.state[7] += ccc;
    hs->ripemd320.state[8] += ddd;
    hs->ripemd320.state[9] += eee;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int ripemd_128_init(hash_state *hs)
{
    hs->ripemd128.state[0] = 0x67452301UL;
    hs->ripemd128.state[1] = 0xefcdab89UL;
    hs->ripemd128.state[2] = 0x98badcfeUL;
    hs->ripemd128.state[3] = 0x10325476UL;
    hs->ripemd128.curlen   = 0;
    hs->ripemd128.length   = 0;

    return NBSCrypto_OK;
}

int ripemd_160_init(hash_state *hs)
{
    hs->ripemd160.state[0] = 0x67452301UL;
    hs->ripemd160.state[1] = 0xefcdab89UL;
    hs->ripemd160.state[2] = 0x98badcfeUL;
    hs->ripemd160.state[3] = 0x10325476UL;
    hs->ripemd160.state[4] = 0xc3d2e1f0UL;
    hs->ripemd160.curlen   = 0;
    hs->ripemd160.length   = 0;

    return NBSCrypto_OK;
}

int ripemd_256_init(hash_state *hs)
{
    hs->ripemd256.state[0] = 0x67452301UL;
    hs->ripemd256.state[1] = 0xefcdab89UL;
    hs->ripemd256.state[2] = 0x98badcfeUL;
    hs->ripemd256.state[3] = 0x10325476UL;
    hs->ripemd256.state[4] = 0x76543210UL;
    hs->ripemd256.state[5] = 0xfedcba98UL;
    hs->ripemd256.state[6] = 0x89abcdefUL;
    hs->ripemd256.state[7] = 0x01234567UL;
    hs->ripemd256.curlen   = 0;
    hs->ripemd256.length   = 0;

    return NBSCrypto_OK;
}

int ripemd_320_init(hash_state *hs)
{
    hs->ripemd320.state[0] = 0x67452301UL;
    hs->ripemd320.state[1] = 0xefcdab89UL;
    hs->ripemd320.state[2] = 0x98badcfeUL;
    hs->ripemd320.state[3] = 0x10325476UL;
    hs->ripemd320.state[4] = 0xc3d2e1f0UL;
    hs->ripemd320.state[5] = 0x76543210UL;
    hs->ripemd320.state[6] = 0xfedcba98UL;
    hs->ripemd320.state[7] = 0x89abcdefUL;
    hs->ripemd320.state[8] = 0x01234567UL;
    hs->ripemd320.state[9] = 0x3c2d1e0fUL;
    hs->ripemd320.curlen   = 0;
    hs->ripemd320.length   = 0;

    return NBSCrypto_OK;
}

int ripemd_128_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;
    if (hs->ripemd128.curlen > sizeof(hs->ripemd128.buf)) {
	return NBSCrypto_ERROR;
    }
    if ((hs->ripemd128.length + inlen * 8) < hs->ripemd128.length) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	if (hs->ripemd128.curlen == 0 && inlen >= 64) {
	    if ((err = _ripemd_128_compress(hs, in)) != NBSCrypto_OK) {
		return err;
	    }
	    hs->ripemd128.length += 64 * 8;
	    in		+= 64;
	    inlen	-= 64;
	} else {
	    n = MIN(inlen, (64 - hs->ripemd128.curlen));
	    memcpy(hs->ripemd128.buf + hs->ripemd128.curlen, in, (size_t)n);
	    hs->ripemd128.curlen += n;
	    in += n;
	    inlen -= n;
	    if (hs->ripemd128.curlen == 64) {
		if ((err = _ripemd_128_compress(hs, hs->ripemd128.buf)) != NBSCrypto_OK) {
		    return err;
		}
		hs->ripemd128.length += 64 * 8;
		hs->ripemd128.curlen = 0;
	    }
	}
    }
    return NBSCrypto_OK;
}

int ripemd_160_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;
    if (hs->ripemd160.curlen > sizeof(hs->ripemd160.buf)) {
	return NBSCrypto_ERROR;
    }
    if ((hs->ripemd160.length + inlen * 8) < hs->ripemd160.length) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	if (hs->ripemd160.curlen == 0 && inlen >= 64) {
	    if ((err = _ripemd_160_compress(hs, in)) != NBSCrypto_OK) {
		return err;
	    }
	    hs->ripemd160.length += 64 * 8;
	    in		+= 64;
	    inlen	-= 64;
	} else {
	    n = MIN(inlen, (64 - hs->ripemd160.curlen));
	    memcpy(hs->ripemd160.buf + hs->ripemd160.curlen, in, (size_t)n);
	    hs->ripemd160.curlen += n;
	    in += n;
	    inlen -= n;
	    if (hs->ripemd160.curlen == 64) {
		if ((err = _ripemd_160_compress(hs, hs->ripemd160.buf)) != NBSCrypto_OK) {
		    return err;
		}
		hs->ripemd160.length += 64 * 8;
		hs->ripemd160.curlen = 0;
	    }
	}
    }
    return NBSCrypto_OK;
}

int ripemd_256_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;
    if (hs->ripemd256.curlen > sizeof(hs->ripemd256.buf)) {
	return NBSCrypto_ERROR;
    }
    if ((hs->ripemd256.length + inlen * 8) < hs->ripemd256.length) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	if (hs->ripemd256.curlen == 0 && inlen >= 64) {
	    if ((err = _ripemd_256_compress(hs, in)) != NBSCrypto_OK) {
		return err;
	    }
	    hs->ripemd256.length += 64 * 8;
	    in		+= 64;
	    inlen	-= 64;
	} else {
	    n = MIN(inlen, (64 - hs->ripemd256.curlen));
	    memcpy(hs->ripemd256.buf + hs->ripemd256.curlen, in, (size_t)n);
	    hs->ripemd256.curlen += n;
	    in += n;
	    inlen -= n;
	    if (hs->ripemd256.curlen == 64) {
		if ((err = _ripemd_256_compress(hs, hs->ripemd256.buf)) != NBSCrypto_OK) {
		    return err;
		}
		hs->ripemd256.length += 64 * 8;
		hs->ripemd256.curlen = 0;
	    }
	}
    }
    return NBSCrypto_OK;
}

int ripemd_320_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long n;
    int err;
    if (hs->ripemd320.curlen > sizeof(hs->ripemd320.buf)) {
	return NBSCrypto_ERROR;
    }
    if ((hs->ripemd320.length + inlen * 8) < hs->ripemd320.length) {
	return NBSCrypto_ERROR;
    }
    while (inlen > 0) {
	if (hs->ripemd320.curlen == 0 && inlen >= 64) {
	    if ((err = _ripemd_320_compress(hs, in)) != NBSCrypto_OK) {
		return err;
	    }
	    hs->ripemd320.length += 64 * 8;
	    in		+= 64;
	    inlen	-= 64;
	} else {
	    n = MIN(inlen, (64 - hs->ripemd320.curlen));
	    memcpy(hs->ripemd320.buf + hs->ripemd320.curlen, in, (size_t)n);
	    hs->ripemd320.curlen += n;
	    in += n;
	    inlen -= n;
	    if (hs->ripemd320.curlen == 64) {
		if ((err = _ripemd_320_compress(hs, hs->ripemd320.buf)) != NBSCrypto_OK) {
		    return err;
		}
		hs->ripemd320.length += 64 * 8;
		hs->ripemd320.curlen = 0;
	    }
	}
    }
    return NBSCrypto_OK;
}

int ripemd_128_done(hash_state *hs, unsigned char *out)
{
    int i;

    if (hs->ripemd128.curlen >= sizeof(hs->ripemd128.buf)) {
	return NBSCrypto_ERROR;
    }

    hs->ripemd128.length += hs->ripemd128.curlen * 8;
    hs->ripemd128.buf[hs->ripemd128.curlen++] = (unsigned char)0x80;

    if (hs->ripemd128.curlen > 56) {
	while (hs->ripemd128.curlen < 64) {
	    hs->ripemd128.buf[hs->ripemd128.curlen++] = (unsigned char)0;
	}
	_ripemd_128_compress(hs, hs->ripemd128.buf);
	hs->ripemd128.curlen = 0;
    }

    while (hs->ripemd128.curlen < 56) {
	hs->ripemd128.buf[hs->ripemd128.curlen++] = (unsigned char)0;
    }

    STORE64L(hs->ripemd128.length, hs->ripemd128.buf+56);
    _ripemd_128_compress(hs, hs->ripemd128.buf);

    for (i = 0; i < 4; i++) {
	STORE32L(hs->ripemd128.state[i], out+(4*i));
    }

    return NBSCrypto_OK;
}

int ripemd_160_done(hash_state *hs, unsigned char *out)
{
    int i;

    if (hs->ripemd160.curlen >= sizeof(hs->ripemd160.buf)) {
	return NBSCrypto_ERROR;
    }

    hs->ripemd160.length += hs->ripemd160.curlen * 8;
    hs->ripemd160.buf[hs->ripemd160.curlen++] = (unsigned char)0x80;

    if (hs->ripemd160.curlen > 56) {
	while (hs->ripemd160.curlen < 64) {
	    hs->ripemd160.buf[hs->ripemd160.curlen++] = (unsigned char)0;
	}
	_ripemd_160_compress(hs, hs->ripemd160.buf);
	hs->ripemd160.curlen = 0;
    }

    while (hs->ripemd160.curlen < 56) {
	hs->ripemd160.buf[hs->ripemd160.curlen++] = (unsigned char)0;
    }

    STORE64L(hs->ripemd160.length, hs->ripemd160.buf+56);
    _ripemd_160_compress(hs, hs->ripemd160.buf);

    for (i = 0; i < 5; i++) {
	STORE32L(hs->ripemd160.state[i], out+(4*i));
    }

    return NBSCrypto_OK;
}

int ripemd_256_done(hash_state *hs, unsigned char *out)
{
    int i;

    if (hs->ripemd256.curlen >= sizeof(hs->ripemd256.buf)) {
	return NBSCrypto_ERROR;
    }

    hs->ripemd256.length += hs->ripemd256.curlen * 8;
    hs->ripemd256.buf[hs->ripemd256.curlen++] = (unsigned char)0x80;

    if (hs->ripemd256.curlen > 56) {
	while (hs->ripemd256.curlen < 64) {
	    hs->ripemd256.buf[hs->ripemd256.curlen++] = (unsigned char)0;
	}
	_ripemd_256_compress(hs, hs->ripemd256.buf);
	hs->ripemd256.curlen = 0;
    }

    while (hs->ripemd256.curlen < 56) {
	hs->ripemd256.buf[hs->ripemd256.curlen++] = (unsigned char)0;
    }

    STORE64L(hs->ripemd256.length, hs->ripemd256.buf+56);
    _ripemd_256_compress(hs, hs->ripemd256.buf);

    for (i = 0; i < 8; i++) {
	STORE32L(hs->ripemd256.state[i], out+(4*i));
    }

    return NBSCrypto_OK;
}

int ripemd_320_done(hash_state *hs, unsigned char *out)
{
    int i;

    if (hs->ripemd320.curlen >= sizeof(hs->ripemd320.buf)) {
	return NBSCrypto_ERROR;
    }

    hs->ripemd320.length += hs->ripemd320.curlen * 8;
    hs->ripemd320.buf[hs->ripemd320.curlen++] = (unsigned char)0x80;

    if (hs->ripemd320.curlen > 56) {
	while (hs->ripemd320.curlen < 64) {
	    hs->ripemd320.buf[hs->ripemd320.curlen++] = (unsigned char)0;
	}
	_ripemd_320_compress(hs, hs->ripemd320.buf);
	hs->ripemd320.curlen = 0;
    }

    while (hs->ripemd320.curlen < 56) {
	hs->ripemd320.buf[hs->ripemd320.curlen++] = (unsigned char)0;
    }

    STORE64L(hs->ripemd320.length, hs->ripemd320.buf+56);
    _ripemd_320_compress(hs, hs->ripemd320.buf);

    for (i = 0; i < 10; i++) {
	STORE32L(hs->ripemd320.state[i], out+(4*i));
    }

    return NBSCrypto_OK;
}
