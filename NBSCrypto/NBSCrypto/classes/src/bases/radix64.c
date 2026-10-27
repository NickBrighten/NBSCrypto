//
//	radix64.c
//

#include "nbs_crypto.h"




static const unsigned char radix64_encode_table[64] = {
    '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
};

static const unsigned char radix64_decode_table[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01,
    0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};




#pragma mark - RADIX64 - Encode
int radix64_encode(const void *in, size_t inlen, unsigned char *out, size_t *outlen)
{
    size_t n;
    unsigned char a;
    unsigned char b;
    unsigned char c;
    unsigned char d;
    const unsigned char *p;

    p = (const unsigned char *)in;
    n = inlen / 3;

    if(inlen == (n * 3 + 1)){
	if(in != NULL && out != NULL){
	    a = (p[n * 3] & 0xFC) >> 2;
	    b = (p[n * 3] & 0x03) << 4;

	    out[n * 4] = radix64_encode_table[a];
	    out[n * 4 + 1] = radix64_encode_table[b];
	    out[n * 4 + 2] = '\0';
	}
	if(outlen != NULL){
	    *outlen = n * 4 + 2;
	}
    }else if(inlen == (n * 3 + 2)){
	if(in != NULL && out != NULL){
	    a = (p[n * 3] & 0xFC) >> 2;
	    b = ((p[n * 3] & 0x03) << 4) | ((p[n * 3 + 1] & 0xF0) >> 4);
	    c = (p[n * 3 + 1] & 0x0F) << 2;

	    out[n * 4]		= radix64_encode_table[a];
	    out[n * 4 + 1]	= radix64_encode_table[b];
	    out[n * 4 + 2]	= radix64_encode_table[c];
	    out[n * 4 + 3]	= '\0';
	}

	if(outlen != NULL){
	    *outlen = n * 4 + 3;
	}
    }else{
	if(out != NULL){
	    out[n * 4] = '\0';
	}
	if(outlen != NULL){
	    *outlen = n * 4;
	}
    }

    if(in != NULL && out != NULL){
	while(n-- > 0){
	    a = (p[n * 3] & 0xFC) >> 2;
	    b = ((p[n * 3] & 0x03) << 4) | ((p[n * 3 + 1] & 0xF0) >> 4);
	    c = ((p[n * 3 + 1] & 0x0F) << 2) | ((p[n * 3 + 2] & 0xC0) >> 6);
	    d = p[n * 3 + 2] & 0x3F;

	    out[n * 4]		= radix64_encode_table[a];
	    out[n * 4 + 1]	= radix64_encode_table[b];
	    out[n * 4 + 2]	= radix64_encode_table[c];
	    out[n * 4 + 3]	= radix64_encode_table[d];
	}
    }
    return NBSCrypto_OK;
}




#pragma mark - RADIX64 - Decode
int radix64_decode(const unsigned char *in, size_t inlen, void *out, size_t *outlen)
{
    int error;
    int c;
    unsigned int value;
    size_t i;
    size_t n;
    unsigned char *p;

    if(in == NULL && inlen != 0){
	return NBSCrypto_ERROR;
    }
    if(outlen == NULL){
	return NBSCrypto_ERROR;
    }

    if((inlen % 4) == 1){
	return NBSCrypto_ERROR;
    }

    error = NBSCrypto_OK;

    p = (unsigned char *) out;
    n = 0;
    value = 0;

    for(i = 0; i < inlen && !error; i++){
	c = (int) in[i];

	if(c < 128 && radix64_decode_table[c] < 64){
	    value = (value << 6) | radix64_decode_table[c];
	    if((i % 4) == 3){
		if(p != NULL){
		    p[n]	= (value >> 16) & 0xFF;
		    p[n + 1]	= (value >>  8) & 0xFF;
		    p[n + 2]	= value & 0xFF;
		}
		n += 3;
		value = 0;
	    }
	}else{
	    error = NBSCrypto_ERROR;
	}
    }

    if(!error){
	if((inlen % 4) == 2){
	    if(p != NULL){
		p[n] = (value >> 4) & 0xFF;
	    }
	    n++;
	}else if((inlen % 4) == 3){
	    if(p != NULL){
		p[n]	= (value >> 10) & 0xFF;
		p[n + 1]= (value >>  2) & 0xFF;
	    }
	    n += 2;
	}else{
	}
    }
    *outlen = n;

    return error;
}
