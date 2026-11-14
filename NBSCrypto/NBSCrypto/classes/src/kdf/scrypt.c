//
//	scrypt.c
//	Authors / Developers		: Colin Percival
//	Last Modified (Original)	: 2009
//

#include "nbs_crypto.h"




#pragma mark - DEFINES

#define LOAD32LE(p) (					\
    ((unsigned)(((unsigned char *)(p))[0]) <<  0) |	\
    ((unsigned)(((unsigned char *)(p))[1]) <<  8) |	\
    ((unsigned)(((unsigned char *)(p))[2]) << 16) |	\
    ((unsigned)(((unsigned char *)(p))[3]) << 24))

#define STORE32LE(a, p)							\
    ((unsigned char *)(p))[0] = ((unsigned)(a) >>  0) & 0xFFU,	\
    ((unsigned char *)(p))[1] = ((unsigned)(a) >>  8) & 0xFFU,	\
    ((unsigned char *)(p))[2] = ((unsigned)(a) >> 16) & 0xFFU,	\
    ((unsigned char *)(p))[3] = ((unsigned)(a) >> 24) & 0xFFU

#define QUARTER_ROUND(a, b, c, d){	\
    b ^= ROL32(a + d,  7);		\
    c ^= ROL32(b + a,  9);		\
    d ^= ROL32(c + b, 13);		\
    a ^= ROL32(d + c, 18);		\
}

#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))




#pragma mark - INLINE
static inline void _salsa20_block(const unsigned char *input, unsigned char *output, int nr)
{
    int i;
    unsigned int x[16];

    for(i = 0; i < 16; i++){
	x[i] = LOAD32LE(input + i * 4);
    }

    for(i = 0; i < nr; i += 2){
	QUARTER_ROUND(x[ 0], x[ 4], x[ 8], x[12]);
	QUARTER_ROUND(x[ 5], x[ 9], x[13], x[ 1]);
	QUARTER_ROUND(x[10], x[14], x[ 2], x[ 6]);
	QUARTER_ROUND(x[15], x[ 3], x[ 7], x[11]);
	QUARTER_ROUND(x[ 0], x[ 1], x[ 2], x[ 3]);
	QUARTER_ROUND(x[ 5], x[ 6], x[ 7], x[ 4]);
	QUARTER_ROUND(x[10], x[11], x[ 8], x[ 9]);
	QUARTER_ROUND(x[15], x[12], x[13], x[14]);
    }

    for(i = 0; i < 16; i++){
	x[i] += LOAD32LE(input + i * 4);
	STORE32LE(x[i], output + i * 4);
    }
}

static inline void _scrypt_xor(unsigned char * restrict x, const unsigned char * restrict a, const unsigned char * restrict b, size_t n)
{
    size_t i = 0;

    for (; i + sizeof(uint64_t) <= n; i += sizeof(uint64_t)) {
	uint64_t va, vb, vx;
	memcpy(&va, a + i, sizeof(va));
	memcpy(&vb, b + i, sizeof(vb));
	vx = va ^ vb;
	memcpy(x + i, &vx, sizeof(vx));
    }

    for (; i < n; i++) {
	x[i] = a[i] ^ b[i];
    }
}

static inline void _scrypt_mix(int r, unsigned char * restrict b, unsigned char * restrict y)
{
    uint64_t x[8];
    const size_t half = (size_t)r * 64;
    const unsigned char *src = b;
    unsigned char *dst_even = y;
    unsigned char *dst_odd  = y + half;

    memcpy(x, b + (2 * (size_t)r - 1) * 64, 64);

    for (int i = 0; i < r; i++) {
	const uint64_t *b_even = (const uint64_t *)src;
	for (int j = 0; j < 8; j++) {
	    x[j] ^= b_even[j];
	}
	_salsa20_block((unsigned char *)x, (unsigned char *)x, 8);
	memcpy(dst_even, x, 64);

	src += 64;
	dst_even += 64;

	const uint64_t *b_odd = (const uint64_t *)src;
	for (int j = 0; j < 8; j++) {
	    x[j] ^= b_odd[j];
	}
	_salsa20_block((unsigned char *)x, (unsigned char *)x, 8);
	memcpy(dst_odd, x, 64);

	src += 64;
	dst_odd += 64;
    }
    memcpy(b, y, (size_t)r * 128);
}

static inline void _scrypt_romix(int r, unsigned char *b, int n, unsigned char *v, unsigned char *y)
{
    int i;
    unsigned int j;
    unsigned char *x;
    unsigned long blockSize;

    blockSize = 128 * r;
    x = b;

    for(i = 0; i < n; i++){
	memcpy(v + i * blockSize, x, blockSize);
	_scrypt_mix(r, x, y);
    }

    for(i = 0; i < n; i++){
	j = LOAD32LE(x + blockSize - 64) & (n - 1);
	_scrypt_xor(x, x, v + j * blockSize, blockSize);
	_scrypt_mix(r, x, y);
    }
}




#pragma mark - FUNCTIONS
int scrypt_hash_password(const unsigned char *key, const unsigned char *salt, int n, int r, int p, unsigned char *out, unsigned long outlen)
{
    int error;
    int i;
    unsigned long blockSize;
    unsigned long keylen, saltlen;
    unsigned char *b = NULL;
    unsigned char *v = NULL;
    unsigned char *y = NULL;


    if(key == NULL || salt == NULL || out == NULL){
	return NBSCrypto_ERROR;
    }

    if(n <= 1 || (n & (n - 1)) != 0){
	return NBSCrypto_ERROR;
    }

    if(r == 0){
	return NBSCrypto_ERROR;
    }

    if(p == 0){
	return NBSCrypto_ERROR;
    }

    keylen = strlen((const char*)key);
    saltlen = strlen((const char*)salt);
    blockSize = 128 * r;

    do{
	b = malloc(p * blockSize);
	if(b == NULL){
	    error = NBSCrypto_ERROR;
	    break;
	}

	v = malloc(n * blockSize);
	if(v == NULL){
	    error = NBSCrypto_ERROR;
	    break;
	}

	y = malloc(blockSize);
	if(y == NULL){
	    error = NBSCrypto_ERROR;
	    break;
	}

	unregister_hash(&sha256_desc);
	register_hash(&sha256_desc);

	error = pbkdf2(PBKDF2_TYPE_HMAC, hash_descriptor[0].ID, (const unsigned char *)key, keylen, salt, saltlen, 1, b, p * blockSize);
	if(error){
	    break;
	}

	for(i = 0; i < p; i++){
	    _scrypt_romix(r, b + i * blockSize, n, v, y);
	}

	error = pbkdf2(PBKDF2_TYPE_HMAC, hash_descriptor[0].ID, (const unsigned char *)key, keylen, b, p * blockSize, 1, out, outlen);
	if(error){
	    break;
	}

	unregister_hash(&sha256_desc);
    } while(0);

    if(b != NULL){
	free(b);
    }

    if(v != NULL){
	free(v);
    }

    if(y != NULL){
	free(y);
    }

    return error;
}

int scrypt_verify_password(const unsigned char *key, const unsigned char *hash)
{
    int error=NBSCrypto_ERROR, dc1=0, n=0, r=0, p=0;
    char **dt1=NULL;
    char salt[256], *temphash=NULL;

    if(key == NULL || hash == NULL){
	return NBSCrypto_ERROR;
    }

    dc1 = splitStr(hash, '$', &dt1);
    if (dc1 < 5 || dt1 == NULL || strcmp("scrypt", dt1[1]) != 0) {
	free(dt1);
	return NBSCrypto_ERROR;
    }

    const char *dt2 = dt1[2];
    while (*dt2 != '\0') {
	if (dt2[0] == 'l' && dt2[1] == 'n' && dt2[2] == '=') {
	    int shift = atoi(dt2 + 3);
	    if (shift > 0 && shift < 31) {
		n = 1 << shift;
	    }
	    dt2 += 3;
	} else if (dt2[1] == '=') {
	    switch (dt2[0]) {
		case 'n': n = atoi(dt2 + 2); break;
		case 'r': r = atoi(dt2 + 2); break;
		case 'p': p = atoi(dt2 + 2); break;
	    }
	    dt2 += 2;
	}
	while (*dt2 != '\0' && *dt2 != ',') {
	    dt2++;
	}
	if (*dt2 == ',') {
	    dt2++;
	}
    }

    if (n <= 0 || r <= 0 || p <= 0) {
	free(dt1);
	return NBSCrypto_ERROR;
    }

    unsigned long sb64len = sizeof(salt);
    if (base64_decode(dt1[3], strlen(dt1[3]), (unsigned char *)salt, &sb64len) != 0 || sb64len >= sizeof(salt)) {
	free(dt1);
	return NBSCrypto_ERROR;
    }
    salt[sb64len] = '\0';

    temphash=dt1[4];
    unsigned long len=strlen(temphash);
    unsigned long outlen=16;

    if		(len>128){outlen=128;}
    else if	(len> 64){outlen= 64;}
    else if	(len> 48){outlen= 48;}
    else if	(len> 32){outlen= 32;}

    unsigned char out[outlen];
    scrypt_hash_password(key, (const unsigned char*)salt, n, r, p, out, outlen);

    unsigned long b64len = (outlen * 2) + 4;
    char b64[b64len];
    base64_encode(out, outlen, b64, &b64len);
    b64[b64len] = '\0';

    if (b64len == len) {
	unsigned char diff = 0;
	for (unsigned long i = 0; i < len; i++) {
	    diff |= (unsigned char)b64[i] ^ (unsigned char)temphash[i];
	}
	if (diff == 0) {
	    error = NBSCrypto_OK;
	}
    }

    free(dt1);

    return error;
}
