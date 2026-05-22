//
//	base16.c
//

#include "nbs_crypto.h"


int base16_decode(const char *in, unsigned long inlen, char *out, unsigned long *outlen)
{
    unsigned long tl = inlen >> 1;
    unsigned long i, j;

    *outlen=tl;

    for (i=j=0;i<tl;i++) {
	unsigned char c = in[j++];
	unsigned char d;

	if 		(c >= '0' && c <= '9') {	d = (c - '0') << 4;
	} else if	(c >= 'a' && c <= 'f') {	d = (c - 'a' + 10) << 4;
	} else if	(c >= 'A' && c <= 'F') {	d = (c - 'A' + 10) << 4;
	} else {
	    return NBSCrypto_ERROR;
	}
	c = in[j++];

	if		(c >= '0' && c <= '9') {	d |= c - '0';
	} else if	(c >= 'a' && c <= 'f') {	d |= c - 'a' + 10;
	} else if	(c >= 'A' && c <= 'F') {	d |= c - 'A' + 10;
	} else {
	    return NBSCrypto_ERROR;
	}
	out[i] = d;
    }
    out[i] = '\0';

    return NBSCrypto_OK;
}

int base16_encode(const unsigned char *in,  unsigned long  inlen, char *out, unsigned long *outlen, unsigned int options)
{
    unsigned long i, x;
    const char *a;
    const char *aT[2] = {"0123456789abcdef", "0123456789ABCDEF"};

    x = inlen*2;
    *outlen=x;

    a=(options==0)?aT[0]:aT[1];

    for (i=0;i<x;i+=2) {
	out[i]   = a[(in[i/2] >> 4) & 0x0f];
	out[i+1] = a[in[i/2] & 0x0f];
    }
    out[x] = '\0';

    return NBSCrypto_OK;
}
