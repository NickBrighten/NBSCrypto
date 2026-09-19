//
//	gmac.c
//	Authors / Developers		: Morris J. Dworkin
//	Last Modified (Original)	: 2007
//

#include "nbs_crypto.h"




#pragma mark DEFINES
#define GMAC_TABLE_N 256
#define GMAC_REVERSE_BITS(n) _reverseInt8(n)

#define STORE32BE(a, p)							\
    ((unsigned char *)(p))[0] = ((unsigned int)(a) >> 24) & 0xFFU,	\
    ((unsigned char *)(p))[1] = ((unsigned int)(a) >> 16) & 0xFFU,	\
    ((unsigned char *)(p))[2] = ((unsigned int)(a) >>  8) & 0xFFU,	\
    ((unsigned char *)(p))[3] = ((unsigned int)(a) >>  0) & 0xFFU

#define STORE64BE(a, p)							\
    ((unsigned char *)(p))[0] = ((unsigned long long)(a) >> 56) & 0xFFU,\
    ((unsigned char *)(p))[1] = ((unsigned long long)(a) >> 48) & 0xFFU,\
    ((unsigned char *)(p))[2] = ((unsigned long long)(a) >> 40) & 0xFFU,\
    ((unsigned char *)(p))[3] = ((unsigned long long)(a) >> 32) & 0xFFU,\
    ((unsigned char *)(p))[4] = ((unsigned long long)(a) >> 24) & 0xFFU,\
    ((unsigned char *)(p))[5] = ((unsigned long long)(a) >> 16) & 0xFFU,\
    ((unsigned char *)(p))[6] = ((unsigned long long)(a) >>  8) & 0xFFU,\
    ((unsigned char *)(p))[7] = ((unsigned long long)(a) >>  0) & 0xFFU

#define betoh32(value) ((unsigned int) (value))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static const unsigned int r[GMAC_TABLE_N] =
{
    0x00000000, 0x01C20000, 0x03840000, 0x02460000, 0x07080000, 0x06CA0000, 0x048C0000, 0x054E0000,
    0x0E100000, 0x0FD20000, 0x0D940000, 0x0C560000, 0x09180000, 0x08DA0000, 0x0A9C0000, 0x0B5E0000,
    0x1C200000, 0x1DE20000, 0x1FA40000, 0x1E660000, 0x1B280000, 0x1AEA0000, 0x18AC0000, 0x196E0000,
    0x12300000, 0x13F20000, 0x11B40000, 0x10760000, 0x15380000, 0x14FA0000, 0x16BC0000, 0x177E0000,
    0x38400000, 0x39820000, 0x3BC40000, 0x3A060000, 0x3F480000, 0x3E8A0000, 0x3CCC0000, 0x3D0E0000,
    0x36500000, 0x37920000, 0x35D40000, 0x34160000, 0x31580000, 0x309A0000, 0x32DC0000, 0x331E0000,
    0x24600000, 0x25A20000, 0x27E40000, 0x26260000, 0x23680000, 0x22AA0000, 0x20EC0000, 0x212E0000,
    0x2A700000, 0x2BB20000, 0x29F40000, 0x28360000, 0x2D780000, 0x2CBA0000, 0x2EFC0000, 0x2F3E0000,
    0x70800000, 0x71420000, 0x73040000, 0x72C60000, 0x77880000, 0x764A0000, 0x740C0000, 0x75CE0000,
    0x7E900000, 0x7F520000, 0x7D140000, 0x7CD60000, 0x79980000, 0x785A0000, 0x7A1C0000, 0x7BDE0000,
    0x6CA00000, 0x6D620000, 0x6F240000, 0x6EE60000, 0x6BA80000, 0x6A6A0000, 0x682C0000, 0x69EE0000,
    0x62B00000, 0x63720000, 0x61340000, 0x60F60000, 0x65B80000, 0x647A0000, 0x663C0000, 0x67FE0000,
    0x48C00000, 0x49020000, 0x4B440000, 0x4A860000, 0x4FC80000, 0x4E0A0000, 0x4C4C0000, 0x4D8E0000,
    0x46D00000, 0x47120000, 0x45540000, 0x44960000, 0x41D80000, 0x401A0000, 0x425C0000, 0x439E0000,
    0x54E00000, 0x55220000, 0x57640000, 0x56A60000, 0x53E80000, 0x522A0000, 0x506C0000, 0x51AE0000,
    0x5AF00000, 0x5B320000, 0x59740000, 0x58B60000, 0x5DF80000, 0x5C3A0000, 0x5E7C0000, 0x5FBE0000,
    0xE1000000, 0xE0C20000, 0xE2840000, 0xE3460000, 0xE6080000, 0xE7CA0000, 0xE58C0000, 0xE44E0000,
    0xEF100000, 0xEED20000, 0xEC940000, 0xED560000, 0xE8180000, 0xE9DA0000, 0xEB9C0000, 0xEA5E0000,
    0xFD200000, 0xFCE20000, 0xFEA40000, 0xFF660000, 0xFA280000, 0xFBEA0000, 0xF9AC0000, 0xF86E0000,
    0xF3300000, 0xF2F20000, 0xF0B40000, 0xF1760000, 0xF4380000, 0xF5FA0000, 0xF7BC0000, 0xF67E0000,
    0xD9400000, 0xD8820000, 0xDAC40000, 0xDB060000, 0xDE480000, 0xDF8A0000, 0xDDCC0000, 0xDC0E0000,
    0xD7500000, 0xD6920000, 0xD4D40000, 0xD5160000, 0xD0580000, 0xD19A0000, 0xD3DC0000, 0xD21E0000,
    0xC5600000, 0xC4A20000, 0xC6E40000, 0xC7260000, 0xC2680000, 0xC3AA0000, 0xC1EC0000, 0xC02E0000,
    0xCB700000, 0xCAB20000, 0xC8F40000, 0xC9360000, 0xCC780000, 0xCDBA0000, 0xCFFC0000, 0xCE3E0000,
    0x91800000, 0x90420000, 0x92040000, 0x93C60000, 0x96880000, 0x974A0000, 0x950C0000, 0x94CE0000,
    0x9F900000, 0x9E520000, 0x9C140000, 0x9DD60000, 0x98980000, 0x995A0000, 0x9B1C0000, 0x9ADE0000,
    0x8DA00000, 0x8C620000, 0x8E240000, 0x8FE60000, 0x8AA80000, 0x8B6A0000, 0x892C0000, 0x88EE0000,
    0x83B00000, 0x82720000, 0x80340000, 0x81F60000, 0x84B80000, 0x857A0000, 0x873C0000, 0x86FE0000,
    0xA9C00000, 0xA8020000, 0xAA440000, 0xAB860000, 0xAEC80000, 0xAF0A0000, 0xAD4C0000, 0xAC8E0000,
    0xA7D00000, 0xA6120000, 0xA4540000, 0xA5960000, 0xA0D80000, 0xA11A0000, 0xA35C0000, 0xA29E0000,
    0xB5E00000, 0xB4220000, 0xB6640000, 0xB7A60000, 0xB2E80000, 0xB32A0000, 0xB16C0000, 0xB0AE0000,
    0xBBF00000, 0xBA320000, 0xB8740000, 0xB9B60000, 0xBCF80000, 0xBD3A0000, 0xBF7C0000, 0xBEBE0000
};




#pragma mark - INLINE
unsigned char _reverseInt8(unsigned char value)
{
    value = ((value & 0xF0) >> 4) | ((value & 0x0F) << 4);
    value = ((value & 0xCC) >> 2) | ((value & 0x33) << 2);
    value = ((value & 0xAA) >> 1) | ((value & 0x55) << 1);

    return value;
}

void _gmac_Mul(gmac_state *context, unsigned char *x)
{
    int i;
    unsigned char b, c;
    unsigned int z[4];

    z[0] = 0;
    z[1] = 0;
    z[2] = 0;
    z[3] = 0;

    for(i = 15; i >= 0; i--){
	b = x[i];
	c = z[0] & 0xFF;
	z[0] = (z[0] >> 8) | (z[1] << 24);
	z[1] = (z[1] >> 8) | (z[2] << 24);
	z[2] = (z[2] >> 8) | (z[3] << 24);
	z[3] >>= 8;

	z[0] ^= context->m[b][0];
	z[1] ^= context->m[b][1];
	z[2] ^= context->m[b][2];
	z[3] ^= context->m[b][3];

	z[3] ^= r[c];
    }

    STORE32BE(z[3], x);
    STORE32BE(z[2], x + 4);
    STORE32BE(z[1], x + 8);
    STORE32BE(z[0], x + 12);
}

void _gmac_XorBlock(unsigned char *x, const unsigned char *a, const unsigned char *b, size_t n)
{
    size_t i;

    for(i = 0; i < n; i++) {
	x[i] = a[i] ^ b[i];
    }
}




#pragma mark - FUNCTIONS

int gmac_init(unsigned long cipher, const unsigned char *key, unsigned long keylen, gmac_state *gmac)
{
    int error, i, j;
    unsigned int c, h[4];

    if(gmac == NULL){
	return NBSCrypto_ERROR;
    }

    if (is_cipher_valid(cipher) != NBSCrypto_OK) {
	return NBSCrypto_ERROR;
    }

    if (cipher_descriptor[cipher].block_length != 16) {
	return NBSCrypto_ERROR;
    }

    gmac->cipher = cipher;

    error = cipher_descriptor[gmac->cipher].setup(key, (int)keylen, 0, &gmac->cs);
    if(error){
	return error;
    }

    h[0] = 0;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;

    cipher_descriptor[gmac->cipher].encrypt((unsigned char *) h, (unsigned char *) h, &gmac->cs);

    j = GMAC_REVERSE_BITS(0);
    gmac->m[j][0] = 0;
    gmac->m[j][1] = 0;
    gmac->m[j][2] = 0;
    gmac->m[j][3] = 0;

    j = GMAC_REVERSE_BITS(1);
    gmac->m[j][0] = betoh32(h[3]);
    gmac->m[j][1] = betoh32(h[2]);
    gmac->m[j][2] = betoh32(h[1]);
    gmac->m[j][3] = betoh32(h[0]);

    for(i = 2; i < 256; i++){
	if((i & 1) != 0){
	    j = GMAC_REVERSE_BITS(i - 1);
	    h[0] = gmac->m[j][0];
	    h[1] = gmac->m[j][1];
	    h[2] = gmac->m[j][2];
	    h[3] = gmac->m[j][3];

	    j = GMAC_REVERSE_BITS(1);
	    h[0] ^= gmac->m[j][0];
	    h[1] ^= gmac->m[j][1];
	    h[2] ^= gmac->m[j][2];
	    h[3] ^= gmac->m[j][3];
	}else{
	    j = GMAC_REVERSE_BITS(i / 2);
	    h[0] = gmac->m[j][0];
	    h[1] = gmac->m[j][1];
	    h[2] = gmac->m[j][2];
	    h[3] = gmac->m[j][3];

	    c = h[0] & 0x01;
	    h[0] = (h[0] >> 1) | (h[1] << 31);
	    h[1] = (h[1] >> 1) | (h[2] << 31);
	    h[2] = (h[2] >> 1) | (h[3] << 31);
	    h[3] >>= 1;

	    h[3] ^= r[GMAC_REVERSE_BITS(1)] & ~(c - 1);
	}

	j = GMAC_REVERSE_BITS(i);
	gmac->m[j][0] = h[0];
	gmac->m[j][1] = h[1];
	gmac->m[j][2] = h[2];
	gmac->m[j][3] = h[3];
    }

    memset(gmac->buffer, 0, cipher_descriptor[gmac->cipher].block_length);
    gmac->bufferLength = 0;
    gmac->totalLength = 0;
    memset(gmac->mac, 0, cipher_descriptor[gmac->cipher].block_length);

    return NBSCrypto_OK;
}

int gmac_setIV(const unsigned char *iv, unsigned long ivlen, gmac_state *gmac)
{
    size_t k;
    size_t n;
    unsigned char b[16];
    unsigned char j[16];

    if(ivlen < 1){
	return NBSCrypto_ERROR;
    }

    if(ivlen == 12){
	memcpy(j, iv, 12);
	STORE32BE(1, j + 12);
    }else{
	memset(j, 0, 16);

	n = ivlen;
	while(n > 0){
	    k = MIN(n, 16);

	    _gmac_XorBlock(j, j, iv, k);
	    _gmac_Mul(gmac, j);

	    iv += k;
	    n -= k;
	}

	memset(b, 0, 8);
	STORE64BE(ivlen * 8, b + 8);

	_gmac_XorBlock(j, j, b, 16);
	_gmac_Mul(gmac, j);
    }

    cipher_descriptor[gmac->cipher].encrypt(j, b, &gmac->cs);
    memcpy(gmac->mac, b, 16);
    memset(gmac->s, 0, 16);
    memset(gmac->buffer, 0, cipher_descriptor[gmac->cipher].block_length);
    gmac->bufferLength = 0;

    return NBSCrypto_OK;
}

int gmac_process(const unsigned char *in, unsigned long inlen, gmac_state *gmac)
{
    size_t n;

    while(inlen > 0){
	n = MIN(inlen, 16 - gmac->bufferLength);
	memcpy(gmac->buffer + gmac->bufferLength, in, n);
	gmac->bufferLength += n;
	gmac->totalLength += n;

	in = (unsigned char *) in + n;
	inlen -= n;

	if(gmac->bufferLength == 16){
	    _gmac_XorBlock(gmac->s, gmac->s, gmac->buffer, 16);
	    _gmac_Mul(gmac, gmac->s);
	    gmac->bufferLength = 0;
	}
    }

    return NBSCrypto_OK;
}

int gmac_done(unsigned char *out, unsigned long *outlen, gmac_state *gmac)
{
    if(gmac == NULL){
	return NBSCrypto_ERROR;
    }

    if(*outlen < 4 || *outlen > 16){
	return NBSCrypto_ERROR;
    }

    if(gmac->bufferLength > 0){
	_gmac_XorBlock(gmac->s, gmac->s, gmac->buffer, gmac->bufferLength);
	_gmac_Mul(gmac, gmac->s);
    }

    STORE64BE(gmac->totalLength * 8, gmac->buffer);
    memset(gmac->buffer + 8, 0, 8);

    _gmac_XorBlock(gmac->s, gmac->s, gmac->buffer, 16);
    _gmac_Mul(gmac, gmac->s);
    _gmac_XorBlock(gmac->mac, gmac->mac, gmac->s, 16);

    if(out != NULL){
	memcpy(out, gmac->mac, *outlen);
    }
    return NBSCrypto_OK;
}
