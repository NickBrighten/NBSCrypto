//
//	md6.c
//	Authors / Developers		: Ronald L. Rivest
//	Last Modified (Original)	: 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor md6_128_desc =
{
    "md6-128",
    10320128,
    16,
    64,
    &md6_128_init,
    &md6_process,
    &md6_done,
    NULL
};

const struct hash_descriptor md6_160_desc =
{
    "md6-160",
    10320160,
    20,
    64,
    &md6_160_init,
    &md6_process,
    &md6_done,
    NULL
};

const struct hash_descriptor md6_192_desc =
{
    "md6-192",
    10320192,
    24,
    64,
    &md6_192_init,
    &md6_process,
    &md6_done,
    NULL
};

const struct hash_descriptor md6_224_desc =
{
    "md6-224",
    10320224,
    28,
    64,
    &md6_224_init,
    &md6_process,
    &md6_done,
    NULL
};

const struct hash_descriptor md6_256_desc =
{
    "md6-256",
    10320256,
    32,
    64,
    &md6_256_init,
    &md6_process,
    &md6_done,
    NULL
};

const struct hash_descriptor md6_384_desc =
{
    "md6-384",
    10320384,
    48,
    64,
    &md6_384_init,
    &md6_process,
    &md6_done,
    NULL
};

const struct hash_descriptor md6_512_desc =
{
    "md6-512",
    10320512,
    64,
    64,
    &md6_512_init,
    &md6_process,
    &md6_done,
    NULL
};




#pragma mark - DEFINES

#define md6_w	64
#define md6_n	89
#define md6_c	16
#define md6_b	64
#define md6_v	(64/md6_w)
#define md6_u	(64/md6_w)
#define md6_k	8
#define md6_q	15

#define w	md6_w
#define n	md6_n
#define c	md6_c
#define b	md6_b
#define v	md6_v
#define u	md6_u
#define k	md6_k
#define q	md6_q

#define md6_default_L 64

#define md6_max_r 255
#define md6_max_stack_height 29


#define t0	17
#define t1	18
#define t2	21
#define t3	31
#define t4	67
#define t5	89


#define min(a,b) ((a)<(b)? (a) : (b))
#define max(a,b) ((a)>(b)? (a) : (b))


#define RL00 loop_body(10,11, 0)
#define RL01 loop_body( 5,24, 1)
#define RL02 loop_body(13, 9, 2)
#define RL03 loop_body(10,16, 3)
#define RL04 loop_body(11,15, 4)
#define RL05 loop_body(12, 9, 5)
#define RL06 loop_body( 2,27, 6)
#define RL07 loop_body( 7,15, 7)
#define RL08 loop_body(14, 6, 8)
#define RL09 loop_body(15, 2, 9)
#define RL10 loop_body( 7,29,10)
#define RL11 loop_body(13, 8,11)
#define RL12 loop_body(11,15,12)
#define RL13 loop_body( 7, 5,13)
#define RL14 loop_body( 6,31,14)
#define RL15 loop_body(12, 9,15)


int md6_byte_order = 0;
#define MD6_LITTLE_ENDIAN (md6_byte_order == 1)
#define MD6_BIG_ENDIAN    (md6_byte_order == 2)


static const uint64_t Q[15] =
{
    0x7311c2812425cfa0ULL, 0x6432286434aac8e7ULL, 0xb60450e9ef68b7c1ULL,
    0xe8fb23908d9f06f1ULL, 0xdd2e76cba691e5bfULL, 0x0cd0d63b2c30bc41ULL,
    0x1f8ccf6823058f8aULL, 0x54e5ed5b88e3775dULL, 0x4ad12aae0a6d6031ULL,
    0x3e7f16bb88222e0dULL, 0x8af8671d3fb50c2cULL, 0x995ad1178bd25c31ULL,
    0xc878c1dd04c4b633ULL, 0x3b72066c7a1552acULL, 0x0d6f3522631effcbULL,
};

const uint64_t S0 = (uint64_t)0x0123456789abcdefULL;
const uint64_t Smask = (uint64_t)0x7311c2812425cfa0ULL;


typedef uint64_t md6_control_word;
typedef uint64_t md6_nodeID;




#pragma mark - INLINE
static inline void _md6_detect_byte_order(void)
{
    uint64_t x = 1 | (((uint64_t)2)<<(w-8));
    unsigned char *cp = (unsigned char *)&x;
    if ( *cp == 1 )        md6_byte_order = 1;
    else if ( *cp == 2 )   md6_byte_order = 2;
    else                   md6_byte_order = 0;
}

static inline uint64_t _md6_byte_reverse(uint64_t x)
{
#define mask8  ((uint64_t)0x00ff00ff00ff00ffULL)
#define mask16 ((uint64_t)0x0000ffff0000ffffULL)
#if (w==64)
    x = (x << 32) | (x >> 32);
#endif
#if (w >= 32)
    x = ((x & mask16) << 16) | ((x & ~mask16) >> 16);
#endif
#if (w >= 16)
    x = ((x & mask8) << 8) | ((x & ~mask8) >> 8);
#endif

    return x;
}

static inline void _md6_reverse_little_endian(uint64_t *x, int count)
{
    int i;
    if (MD6_LITTLE_ENDIAN)
	for (i=0;i<count;i++)
	    x[i] = _md6_byte_reverse(x[i]);
}

static inline void _md6_append_bits(unsigned char *dest, unsigned int destlen, unsigned char *src, unsigned int srclen)
{
    int i, di, accumlen;
    uint16_t accum;
    int srcbytes;

    if (srclen == 0) return;

    accum = 0;
    accumlen = 0;
    if (destlen%8 != 0){
	accumlen = destlen%8;
	accum = dest[destlen/8];
	accum = accum >> (8-accumlen);
    }
    di = destlen/8;

    srcbytes = (srclen+7)/8;
    for (i=0;i<srcbytes;i++){
	if (i != srcbytes-1){
	    accum = (accum << 8) ^ src[i];
	    accumlen += 8;
	}else{
	    int newbits = ((srclen%8 == 0) ? 8 : (srclen%8));
	    accum = (accum << newbits) | (src[i] >> (8-newbits));
	    accumlen += newbits;
	}

	while ( ((i != srcbytes-1) & (accumlen >= 8)) || ((i == srcbytes-1) & (accumlen > 0)) ){
	    int numbits = min(8,accumlen);
	    unsigned char bits;
	    bits = accum >> (accumlen - numbits);
	    bits = bits << (8-numbits);
	    bits &= (0xff00 >> numbits);
	    dest[di++] = bits;
	    accumlen -= numbits;
	}
    }
}

static inline md6_control_word _md6_make_control_word(int r, int L, int z, int p, int keylen, int d)
{
    md6_control_word V;
    V = ((((md6_control_word) 0) << 60) |
	 (((md6_control_word) r) << 48) |
	 (((md6_control_word) L) << 40) |
	 (((md6_control_word) z) << 36) |
	 (((md6_control_word) p) << 20) |
	 (((md6_control_word) keylen) << 12 ) |
	 (((md6_control_word) d)) );
    return V;
}

static inline md6_nodeID _md6_make_nodeID(int ell,int i)
{
    md6_nodeID U;
    U = ((((md6_nodeID) ell) << 56) |
	 ((md6_nodeID) i) );
    return U;
}

static inline int _md6_default_r(int d, int keylen)
{
    int r;

    r = 40 + (d/4);

    if (keylen>0)
	r = max(80,r);

    return r;
}

static inline void _md6_main_compression_loop(uint64_t *A , int r)
{
    uint64_t x, S;
    int i,j;

    S = S0;
    for (j = 0, i = n; j<r*c; j+=c){

	/* ******************************************* */
#define loop_body(rs,ls,step)			\
    x = S;					\
    x ^= A[i+step-t5];				\
    x ^= A[i+step-t0];				\
    x ^= ( A[i+step-t1] & A[i+step-t2] );	\
    x ^= ( A[i+step-t3] & A[i+step-t4] );	\
    x ^= (x >> rs);				\
    A[i+step] = x ^ (x << ls);
	/* ******************************************* */

	RL00 RL01 RL02 RL03 RL04 RL05 RL06 RL07
	RL08 RL09 RL10 RL11 RL12 RL13 RL14 RL15

	S = (S << 1) ^ (S >> (w-1)) ^ (S & Smask);
	i += 16;
    }
}

static inline int _md6_compress(uint64_t *C, uint64_t *N, int r, uint64_t *A)
{
    uint64_t *A_as_given = A;

    if ( N == NULL) return NBSCrypto_ERROR;
    if ( C == NULL) return NBSCrypto_ERROR;
    if ( r<0 || r > md6_max_r) return NBSCrypto_ERROR;

    if ( A == NULL) A = calloc(r*c+n,sizeof(uint64_t));
    if ( A == NULL) return NBSCrypto_ERROR;

    memcpy(A, N, n*sizeof(uint64_t) );

    _md6_main_compression_loop( A, r );

    memcpy(C, A+(r-1)*c+n, c*sizeof(uint64_t) );

    if(A_as_given == NULL){
	memset(A,0,(r*c+n)*sizeof(uint64_t));
	free(A);
    }

    return NBSCrypto_OK;
}

static inline void _md6_pack(uint64_t *N, const uint64_t *Q, uint64_t *K, int ell, int i, int r, int L, int z, int p, int keylen, int d, uint64_t *B)
{
    int j;
    int ni;
    md6_nodeID U;
    md6_control_word V;

    ni = 0;

    for (j=0;j<q;j++) N[ni++] = Q[j];
    for (j=0;j<k;j++) N[ni++] = K[j];

    U = _md6_make_nodeID(ell, i);
    memcpy((unsigned char *)&N[ni], &U, min(u*(w/8), sizeof(md6_nodeID)));
    ni += u;

    V = _md6_make_control_word(r, L, z, p, keylen, d);
    memcpy((unsigned char *)&N[ni], &V, min(v*(w/8), sizeof(md6_control_word)));
    ni += v;

    memcpy(N+ni,B,b*sizeof(uint64_t));
}

static inline int _md6_standard_compress(uint64_t *C, const uint64_t *Q, uint64_t *K, int ell, int i, int r, int L, int z, int p, int keylen, int d, uint64_t *B)
{
    uint64_t N[md6_n];
    uint64_t A[5000];

    if ( C == NULL ) return NBSCrypto_ERROR;
    if ( B == NULL ) return NBSCrypto_ERROR;
    if ( (r<0) | (r>md6_max_r) ) return NBSCrypto_ERROR;
    if ( (L<0) | (L>255) ) return NBSCrypto_ERROR;
    if ( (ell < 0) || (ell > 255) ) return NBSCrypto_ERROR;
    if ( (p < 0) || (p > b*w ) ) return NBSCrypto_ERROR;
    if ( (d <= 0) || (d > c*w/2) ) return NBSCrypto_ERROR;
    if ( K == NULL ) return NBSCrypto_ERROR;
    if ( Q == NULL ) return NBSCrypto_ERROR;

    _md6_pack(N, Q, K, ell, i, r, L, z, p, keylen, d, B);

    return _md6_compress(C, N, r, A);
}

static inline int _md6_compress_block(uint64_t *C, hash_state *hs, int ell, int z)
{
    int p, err;

    if ( hs == NULL) return NBSCrypto_ERROR;
    if ( hs->md6.initialized == 0 ) return NBSCrypto_ERROR;
    if ( ell < 0 ) return NBSCrypto_ERROR;
    if ( ell >= md6_max_stack_height-1 ) return NBSCrypto_ERROR;

    hs->md6.compression_calls++;

    if (ell==1){
	if (ell<(hs->md6.L + 1))
	    _md6_reverse_little_endian(&(hs->md6.B[ell][0]),b);
	else
	    _md6_reverse_little_endian(&(hs->md6.B[ell][c]),b-c);
    }

    p = b*w - hs->md6.bits[ell];

    err = _md6_standard_compress( C, Q, hs->md6.K, ell, (int)hs->md6.i_for_level[ell], hs->md6.r, hs->md6.L, z, p, hs->md6.keylen, hs->md6.d, hs->md6.B[ell]);
    if (err) return err;

    hs->md6.bits[ell] = 0;
    hs->md6.i_for_level[ell]++;

    memset(&(hs->md6.B[ell][0]), 0, b*sizeof(uint64_t));

    return NBSCrypto_OK;
}

static inline int _md6_internal_process(hash_state *hs, int ell, int final)
{
    int err, z, next_level;
    uint64_t C[c];

    if ( hs == NULL) return NBSCrypto_ERROR;
    if ( hs->md6.initialized == 0 ) return NBSCrypto_ERROR;

    if (!final){
	if ( hs->md6.bits[ell] < b*w ){
	    return NBSCrypto_OK;
	}
    }else
    { if ( ell == hs->md6.top )
    { if (ell == (hs->md6.L + 1))
    { if ( hs->md6.bits[ell]==c*w && hs->md6.i_for_level[ell]>0 )
	return NBSCrypto_OK;
    }else{
	if ( ell>1 && hs->md6.bits[ell]==c*w)
	    return NBSCrypto_OK;
    }
    }
    }

    z = 0; if (final && (ell == hs->md6.top)) z = 1;
    if ((err = _md6_compress_block(C, hs, ell, z)))
	return err;
    if (z==1){
	memcpy( hs->md6.hashval, C, md6_c*(w/8) );
	return NBSCrypto_OK;
    }

    next_level = min(ell+1, hs->md6.L+1);

    if (next_level == hs->md6.L + 1
	&& hs->md6.i_for_level[next_level]==0
	&& hs->md6.bits[next_level]==0 )
	hs->md6.bits[next_level] = c*w;

    memcpy((char *)hs->md6.B[next_level] + hs->md6.bits[next_level]/8, C, c*(w/8));
    hs->md6.bits[next_level] += c*w;
    if (next_level > hs->md6.top) hs->md6.top = next_level;

    return _md6_internal_process(hs, next_level, final);
}

static inline int md6_full_init(hash_state *hs, int d, unsigned char *key, int keylen, int L, int r)
{
    if (hs == NULL) return NBSCrypto_ERROR;
    if ( (key != NULL) && ((keylen < 0) || (keylen > k*(w/8))) )
	return NBSCrypto_ERROR;
    if ( d < 1 || d > 512 || d > w*c/2 ) return NBSCrypto_ERROR;

    _md6_detect_byte_order();
    memset(hs, 0, sizeof(hs->md6));
    hs->md6.d = d;
    if (key != NULL && keylen > 0){
	memcpy(hs->md6.K, key, keylen);
	hs->md6.keylen = keylen;
	_md6_reverse_little_endian(hs->md6.K, k);
    }else{
	hs->md6.keylen = 0;
    }
    if ( (L<0) | (L>255) ) return NBSCrypto_ERROR;
    hs->md6.L = L;
    if ( (r<0) | (r>255) ) return NBSCrypto_ERROR;
    hs->md6.r = r;
    hs->md6.initialized = 1;
    hs->md6.top = 1;
    if (L==0) hs->md6.bits[1] = c*w;

    return NBSCrypto_OK;
}

static inline int _init_md6(hash_state *hs, int d)
{
    return md6_full_init(hs, d, NULL, 0, md6_default_L, _md6_default_r(d, 0));
}

static inline int _update_md6(hash_state *hs, unsigned char *data, uint64_t databitlen)
{
    unsigned int j, portion_size;
    int err;

    if ( hs == NULL ) return NBSCrypto_ERROR;
    if ( hs->md6.initialized == 0 ) return NBSCrypto_ERROR;
    if ( data == NULL ) return NBSCrypto_ERROR;

    j = 0;
    while (j<databitlen){
	portion_size = min((int)databitlen-j, (unsigned int)(b*w-(hs->md6.bits[1])));

	if ((portion_size % 8 == 0) && (hs->md6.bits[1] % 8 == 0) && (j % 8 == 0)){
	    memcpy((char *)hs->md6.B[1] + hs->md6.bits[1]/8, &(data[j/8]), portion_size/8);
	}else{
	    _md6_append_bits((unsigned char *)hs->md6.B[1], hs->md6.bits[1], &(data[j/8]), portion_size);
	}

	j += portion_size;
	hs->md6.bits[1] += portion_size;
	hs->md6.bits_processed += portion_size;

	if (hs->md6.bits[1] == b*w && j<databitlen){
	    if ((err=_md6_internal_process(hs, 1, 0)))
		return err;
	}
    }

    return NBSCrypto_OK;
}

static inline int _final_md6(hash_state *hs, unsigned char *hashval)
{
    int ell, err;

    if ( hs == NULL) return NBSCrypto_ERROR;
    if ( hs->md6.initialized == 0 ) return NBSCrypto_ERROR;

    if ( hs->md6.finalized == 1 ) return NBSCrypto_OK;

    if (hs->md6.top == 1) ell = 1;
    else for (ell=1; ell<=hs->md6.top; ell++)
	if (hs->md6.bits[ell]>0) break;

    err = _md6_internal_process(hs, ell, 1);
    if (err) return err;

    _md6_reverse_little_endian((uint64_t*)hs->md6.hashval, c);
    if (hashval != NULL) memcpy(hashval, hs->md6.hashval, (hs->md6.d+7)/8);

    hs->md6.finalized = 1;

    return NBSCrypto_OK;
}

static inline int _md6_init(hash_state *hs, int hashbitlen)
{
    int err;
    if ((err = _init_md6(hs, hashbitlen)))
	return err;
    hs->md6.hashbitlen = hashbitlen;
    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int md6_128_init(hash_state *hs){return _md6_init(hs, 128);}
int md6_160_init(hash_state *hs){return _md6_init(hs, 160);}
int md6_192_init(hash_state *hs){return _md6_init(hs, 192);}
int md6_224_init(hash_state *hs){return _md6_init(hs, 224);}
int md6_256_init(hash_state *hs){return _md6_init(hs, 256);}
int md6_384_init(hash_state *hs){return _md6_init(hs, 384);}
int md6_512_init(hash_state *hs){return _md6_init(hs, 512);}

int md6_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    return _update_md6(hs, (unsigned char *)in, (uint64_t)inlen);
}

int md6_done(hash_state *hs, unsigned char *out)
{
    return _final_md6(hs, (unsigned char *) out);
}
