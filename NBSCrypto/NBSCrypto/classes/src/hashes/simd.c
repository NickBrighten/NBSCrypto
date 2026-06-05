//
//	simd.c
//	Authors / Developers		: Gaëtan Leurent, Charles Bouillaguet, Pierre-Alain Fouque
//	Last Modified (Original)	: 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor simd_224_desc =
{
    "simd-224",
    207,
    28,
    64,
    &simd_224_init,
    &simd_process,
    &simd_done,
    NULL
};

const struct hash_descriptor simd_256_desc =
{
    "simd-256",
    208,
    32,
    64,
    &simd_256_init,
    &simd_process,
    &simd_done,
    NULL
};

const struct hash_descriptor simd_384_desc =
{
    "simd-384",
    209,
    32,
    64,
    &simd_384_init,
    &simd_process,
    &simd_done,
    NULL
};

const struct hash_descriptor simd_512_desc =
{
    "simd-512",
    210,
    64,
    64,
    &simd_512_init,
    &simd_process,
    &simd_done,
    NULL
};




#pragma mark - DEFINES

#define C32(x) ((uint32_t)(x))
#define T32(x) ((x) & C32(0xFFFFFFFF))
#define ROTL32(x, n) T32(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n) ROTL32(x, (32 - (n)))

#define CHECK_ALIGNED(p,n) ((((unsigned char *) (p) - (unsigned char *) NULL) & ((n)-1)) == 0)
#define IS_ALIGNED(p,n) (n<=4 || CHECK_ALIGNED(p,n))

const int P[32] = {
    4, 6, 0, 2, 7, 5, 3, 1,
    15,11,12, 8, 9,13,10,14,
    17,18,23,20,22,21,16,19,
    30,24,25,31,27,29,28,26
};

const int p4[4][8] = {
    {1,2,3,0},
    {2,3,0,1},
    {1,2,3,0},
    {2,3,0,1}
};

const int p8[4][8] = {
    {1,0,3,2,5,4,7,6},
    {2,3,0,1,6,7,4,5},
    {7,6,5,4,3,2,1,0},
    {4,5,6,7,0,1,2,3}
};

static const uint32_t IV_224[] = {
    0x2bcc3476, 0x64dce6a3, 0xbabf841b, 0xcf1bb3a2, 0x1389afa5, 0x8818544b, 0x83140916, 0x9525c82b,
    0x42b233fc, 0xf332c0dc, 0x597129f0, 0x7c8f6a8d, 0xfe2c7137, 0x3385203b, 0x841742af, 0xbcfe0e48
};

static const uint32_t IV_256[] = {
    0x96301f14, 0x64f69407, 0x8450cc02, 0x42c538e3, 0x75ad94b4, 0x8b618939, 0x5a13cb35, 0x26141ded,
    0x2d83bbab, 0x0c195501, 0xcc0782ba, 0x356688a2, 0x5731b59d, 0xabff7dd4, 0xdb4cd0f5, 0x7240ec03
};

static const uint32_t IV_384[] = {
    0x0d14da0d, 0x95c2d7d5, 0xa95b8260, 0xb4722c01, 0xe4be208b, 0x12cb4873, 0x67773662, 0x56a66d24,
    0xfba71944, 0x6e1b3ca0, 0x7d0b1a7c, 0xb506d742, 0xc417ab0b, 0xeb34f21c, 0xbab7945b, 0xd1ed927e,
    0xe65ced88, 0xb0667012, 0x916393e6, 0x4b0643ce, 0x4fbed3f1, 0x9627d2bc, 0xeb96513b, 0x9aa6c3e3,
    0xf8773176, 0x4c45a87d, 0xc3280609, 0xe6996ca4, 0x694e541f, 0x0e3dcf80, 0x042ab187, 0x71fb0b87
};

static const uint32_t IV_512[] = {
    0xc2956828, 0x3da33320, 0x4149c566, 0xc49d9244, 0x04a3f1aa, 0x0220c98b, 0x7246bebf, 0xe51d9d96,
    0x39369835, 0xb7b6f593, 0x956d5c2e, 0x2e4e80c8, 0x1e9fc449, 0x84ca34e9, 0x17d45ec5, 0x27db1b31,
    0xd9ca7181, 0xcf8e8183, 0xe2f28feb, 0xe9aa51c5, 0xc5c2d649, 0x37c0b473, 0x07eef0a5, 0xdd23d692,
    0x4d6185f6, 0xbbdcbc6e, 0x753b2bf6, 0x7aac68ac, 0xeb672a56, 0xed8a5dcd, 0xb072020d, 0xb07cf71f
};

typedef uint32_t ( * boolean_function) (const uint32_t, const uint32_t, const uint32_t);
typedef int fft_t;




#pragma mark - INLINE

static inline uint32_t _IF(const uint32_t x, const uint32_t y, const uint32_t z)
{
    return (x & y) | (~x & z);
}

static inline uint32_t _MAJ(const uint32_t x, const uint32_t y, const uint32_t z)
{
    return (z & y) | ((z | y) & x);
}

static inline int _requiredAlignment(void) {
    return 1;
}

static inline void _increaseCounter(hash_state *hs, unsigned long inlen) {
    hs->simd.count += inlen;
}

static inline void _message_expansion(hash_state * const hs, uint32_t W[32][8], const unsigned char * const M, int final)
{
    fft_t y[256];

    const int n = hs->simd.n_feistels;
    const int alpha = (n == 4) ? 139 : 41;

    int beta = (n == 4) ? 98 : 163;
    int beta_i = 1;
    int j,i;
    int alpha_i = 1;
    uint32_t Z[32][8];

    const int fft_size = (n==4) ? 128 : 256;
    const int M_size = (n==4) ? 64 : 128;

    for(i=0; i<fft_size; i++) {
	y[i] = beta_i;
	beta_i = (beta_i * beta) % 257;
    }

    if (final) {
	beta = (n == 4) ? 58 : 40;
	beta_i = 1;
	for(i=0; i<fft_size; i++) {
	    y[i] += beta_i;
	    beta_i = (beta_i * beta) % 257;
	}
    }

    for(i=0; i<fft_size; i++) {
	int alpha_ij = 1;
	for(j=0; j<M_size; j++) {
	    y[i] = (y[i] + alpha_ij * M[j]) % 257;
	    alpha_ij = (alpha_ij * alpha_i) % 257;
	}
	alpha_i = (alpha_i * alpha) % 257;
    }

    for(i=0; i<fft_size; i++){
	if (y[i] > 128){
	    y[i] -= 257;
	}
    }

    for(i=0; i<16; i++){
	for(j=0; j<n; j++){
	    Z[i][j] = (((uint32_t) (y[2*i*n+2*j] * 185)) & 0xffff) | ((uint32_t) (y[2*i*n+2*j+1] * 185) << 16);
	}
    }

    for(i=0; i<8; i++){
	for(j=0; j<n; j++){
	    Z[i+16][j] = (((uint32_t) (y[2*i*n+2*j] * 233)) & 0xffff) | ((uint32_t) (y[2*i*n+2*j+fft_size/2] * 233) << 16);
	}
    }

    for(i=0; i<8; i++){
	for(j=0; j<n; j++){
	    Z[i+24][j] = (((uint32_t) (y[2*i*n+2*j+1] * 233)) & 0xffff) | ((uint32_t) (y[2*i*n+2*j+fft_size/2+1] * 233) << 16);
	}
    }

    for(i=0; i<32; i++){
	for(j=0; j<n; j++){
	    W[i][j] = Z[P[i]][j];
	}
    }
}

static inline int _simd_supported_length(int hashbitlen) {
    if (hashbitlen <= 0 || hashbitlen > 512){
	return 0;
    }else{
	return 1;
    }
}

static inline void _simd_step(hash_state *hs, const uint32_t w[8], const int i, const int r, const int s, const boolean_function F)
{
    int n = hs->simd.n_feistels;
    uint32_t tmp[8];
    int j;
    const int * perm;

    for(j=0; j < n; j++){
	tmp[j] = ROTL32(hs->simd.A[j], r);
    }

    if (n == 4){
	perm = &p4[i % 4][0];
    }else{
	perm = &p8[i % 4][0];
    }

    for(j=0; j < n; j++){
	int p = perm[j];
	hs->simd.A[j] = hs->simd.D[j] + w[j] + F(hs->simd.A[j], hs->simd.B[j], hs->simd.C[j]);
	hs->simd.A[j] = T32(ROTL32(T32(hs->simd.A[j]), s) + tmp[p]);
	hs->simd.D[j] = hs->simd.C[j];
	hs->simd.C[j] = hs->simd.B[j];
	hs->simd.B[j] = tmp[j];
    }
}

static inline void _simd_round(hash_state * const hs, uint32_t w[32][8], const int i, const int r, const int s, const int t, const int u)
{
    _simd_step(hs, w[8*i],   8*i,   r, s, _IF);
    _simd_step(hs, w[8*i+1], 8*i+1, s, t, _IF);
    _simd_step(hs, w[8*i+2], 8*i+2, t, u, _IF);
    _simd_step(hs, w[8*i+3], 8*i+3, u, r, _IF);

    _simd_step(hs, w[8*i+4], 8*i+4, r, s, _MAJ);
    _simd_step(hs, w[8*i+5], 8*i+5, s, t, _MAJ);
    _simd_step(hs, w[8*i+6], 8*i+6, t, u, _MAJ);
    _simd_step(hs, w[8*i+7], 8*i+7, u, r, _MAJ);
}

static inline void _simd_compress(hash_state * const hs, const unsigned char * const M, int final)
{
    uint32_t W[32][8];
    uint32_t IV[4][8];
    int i,j;
    const int n = hs->simd.n_feistels;

    for(i=0; i<n; i++){
	IV[0][i] = hs->simd.A[i];
	IV[1][i] = hs->simd.B[i];
	IV[2][i] = hs->simd.C[i];
	IV[3][i] = hs->simd.D[i];
    }

    _message_expansion(hs, W,  M, final);

#define PACK(i)(			\
    (((uint32_t) M[i]))		^	\
    (((uint32_t) M[i+1]) <<  8)	^	\
    (((uint32_t) M[i+2]) << 16)	^	\
    (((uint32_t) M[i+3]) << 24))

    for(j=0; j<n; j++){
	hs->simd.A[j] ^= PACK(4*j);
	hs->simd.B[j] ^= PACK(4*j+4*n);
	hs->simd.C[j] ^= PACK(4*j+8*n);
	hs->simd.D[j] ^= PACK(4*j+12*n);
    }

#undef PACK

    _simd_round(hs, W, 0, 3,  20, 14, 27);
    _simd_round(hs, W, 1, 26,  4, 23, 11);
    _simd_round(hs, W, 2, 19, 28,  7, 22);
    _simd_round(hs, W, 3, 15,  5, 29, 9);

    _simd_step(hs, IV[0], 0, 15, 5, _IF);
    _simd_step(hs, IV[1], 1, 5, 29, _IF);
    _simd_step(hs, IV[2], 2, 29, 9, _IF);
    _simd_step(hs, IV[3], 3, 9, 15, _IF);
}

static inline int _simd_init_iv(hash_state *hs, int hashbitlen, const uint32_t *IV)
{
    int n;

    if (!_simd_supported_length(hashbitlen))
	return NBSCrypto_ERROR;

    n = (hashbitlen <= 256) ? 4 : 8;

    hs->simd.hashbitlen = hashbitlen;
    hs->simd.n_feistels = n;
    hs->simd.blocksize = 128*n;

    hs->simd.count = 0;

    hs->simd.buffer = malloc(16*n + 16);
    hs->simd.buffer += ((unsigned char*)NULL - hs->simd.buffer)&15;

    hs->simd.A = malloc((4*n+4)*sizeof(uint32_t));
    hs->simd.A += ((uint32_t*)NULL - hs->simd.A)&3;

    hs->simd.B = hs->simd.A+n;
    hs->simd.C = hs->simd.B+n;
    hs->simd.D = hs->simd.C+n;

    if (IV)
	memcpy(hs->simd.A, IV, 4*n*sizeof(uint32_t));
    else
	memset(hs->simd.A, 0, 4*n*sizeof(uint32_t));

    return NBSCrypto_OK;
}

static inline int _simd_init(hash_state *hs, int hashbitlen)
{
    int r;
    char *init;

    if (hashbitlen == 224){
	r=_simd_init_iv(hs, hashbitlen, IV_224);
    }else if (hashbitlen == 256){
	r=_simd_init_iv(hs, hashbitlen, IV_256);
    }else if (hashbitlen == 384){
	r=_simd_init_iv(hs, hashbitlen, IV_384);
    }else if (hashbitlen == 512){
	r=_simd_init_iv(hs, hashbitlen, IV_512);
    }else{
	r=_simd_init_iv(hs, hashbitlen, NULL);
	if (r != NBSCrypto_OK)
	    return r;

	init = malloc(hs->simd.blocksize);
	memset(init, 0, hs->simd.blocksize);

	_simd_compress(hs, (unsigned char*) init, 0);
	free(init);
    }
    return r;
}




#pragma mark - FUNCTIONS

int simd_224_init(hash_state *hs){return _simd_init(hs, 224);}
int simd_256_init(hash_state *hs){return _simd_init(hs, 256);}
int simd_384_init(hash_state *hs){return _simd_init(hs, 384);}
int simd_512_init(hash_state *hs){return _simd_init(hs, 512);}

int simd_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned current;
    unsigned int bs = hs->simd.blocksize;
    static int align = -1;

    if (align == -1){
	align = _requiredAlignment();
    }

    current = hs->simd.count & (bs - 1);

    if(current & 7){
	return NBSCrypto_ERROR;
    }

    while (inlen > 0) {
	if (IS_ALIGNED(in,align) && current == 0 && inlen >= bs) {
	    _simd_compress(hs, in, 0);
	    inlen -= bs;
	    in += bs/8;
	    _increaseCounter(hs, bs);
	} else {
	    unsigned int len = bs - current;
	    if (inlen < len) {
		memcpy(hs->simd.buffer+current/8, in, (inlen+7)/8);
		_increaseCounter(hs, inlen);
		return NBSCrypto_OK;
	    } else {
		memcpy(hs->simd.buffer+current/8, in, len/8);
		_increaseCounter(hs,len);
		inlen -= len;
		in += len/8;
		current = 0;
		_simd_compress(hs, hs->simd.buffer, 0);
	    }
	}
    }
    return NBSCrypto_OK;
}

int simd_done(hash_state *hs, unsigned char *out) {
    unsigned long long l;
    unsigned int i;
    unsigned char bs[64];

    if (hs->simd.count & (hs->simd.blocksize - 1)) {
	int current = hs->simd.count & (hs->simd.blocksize - 1);
	if (current & 7) {
	    unsigned char mask = 0xff >> (current&7);
	    hs->simd.buffer[current/8] &= ~mask;
	}
	current = (current+7)/8;
	memset(hs->simd.buffer+current, 0, hs->simd.blocksize/8 - current);
	_simd_compress(hs, hs->simd.buffer, 0);
    }
    memset(hs->simd.buffer, 0, hs->simd.blocksize/8);

    l = hs->simd.count;
    for (i=0; i<8; i++) {
	hs->simd.buffer[i] = l & 0xff;
	l >>= 8;
    }

    _simd_compress(hs, hs->simd.buffer, 1);

    for (i=0; i<2*hs->simd.n_feistels; i++) {
	uint32_t x = hs->simd.A[i];
	bs[4*i  ] = x&0xff;
	x >>= 8;
	bs[4*i+1] = x&0xff;
	x >>= 8;
	bs[4*i+2] = x&0xff;
	x >>= 8;
	bs[4*i+3] = x&0xff;
    }

    memcpy(out, bs, hs->simd.hashbitlen/8);
    if (hs->simd.hashbitlen%8) {
	unsigned char mask = 0xff << (8 - (hs->simd.hashbitlen%8));
	out[hs->simd.hashbitlen/8 + 1] = bs[hs->simd.hashbitlen/8 + 1] & mask;
    }

    return NBSCrypto_OK;
}
