//
//	kmac.c
//	Authors / Developers		: Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche.
//	Last Modified (Original)	: 2016
//

#include "nbs_crypto.h"




#pragma mark - DEFINES
#define _KMAC128       1
#define _KMAC256       2
#define _KMAC128_XOF   3
#define _KMAC256_XOF   4




#pragma mark - INLINE
static inline unsigned long _left_encode(unsigned long long x, unsigned char *out)
{
    int i, n = 1;
    for (i = 7; i > 0; --i) {
	if ((x >> (i * 8)) & 0xff) {
	    n = i + 1;
	    break;
	}
    }
    out[0] = (unsigned char)n;
    for (i = 0; i < n; ++i) {
	out[1 + i] = (unsigned char)(x >> ((n - 1 - i) * 8));
    }
    return (unsigned long)(n + 1);
}

static inline unsigned long _right_encode(unsigned long long x, unsigned char *out)
{
    int i, n = 1;
    for (i = 7; i > 0; --i) {
	if ((x >> (i * 8)) & 0xff) {
	    n = i + 1;
	    break;
	}
    }
    for (i = 0; i < n; ++i) {
	out[i] = (unsigned char)(x >> ((n - 1 - i) * 8));
    }
    out[n] = (unsigned char)n;
    return (unsigned long)(n + 1);
}

static inline int _feed_bytepad_prefix(hash_state *hs, unsigned long rate, unsigned long *total)
{
    unsigned char enc[9];
    unsigned long enclen = _left_encode(rate, enc);
    int err = sha3_process(hs, enc, enclen);
    if (err == NBSCrypto_OK) *total = enclen;
    return err;
}

static inline int _feed_bytepad_zero_fill(hash_state *hs, unsigned long rate, unsigned long total)
{
    unsigned long pad = (rate - (total % rate)) % rate;
    if (pad != 0) {
	unsigned char zeros[rate];
	memset(zeros, 0, sizeof(zeros));
	return sha3_process(hs, zeros, pad);
    }
    return NBSCrypto_OK;
}

static inline int _feed_encode_string(hash_state *hs, const unsigned char *s, unsigned long slen, unsigned long *total)
{
    unsigned char enc[9];
    unsigned long enclen;
    int err;
    enclen = _left_encode((unsigned long long)slen * 8, enc);
    if ((err = sha3_process(hs, enc, enclen)) != NBSCrypto_OK) return err;
    *total += enclen;
    if (slen != 0) {
	if ((err = sha3_process(hs, s, slen)) != NBSCrypto_OK) return err;
	*total += slen;
    }
    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int kmac_init(int variant, const unsigned char *key, unsigned long keylen, const unsigned char *cust, unsigned long custlen, kmac_state *kmac)
{
    static const unsigned char kmac_name[4] = { 'K', 'M', 'A', 'C' };
    int err, num;
    unsigned long rate, total;

    switch (variant) {
	case _KMAC128:{		num = 128; kmac->xof = 0; rate = 168; break;}
	case _KMAC256:{		num = 256; kmac->xof = 0; rate = 136; break;}
	case _KMAC128_XOF:{	num = 128; kmac->xof = 1; rate = 168; break;}
	case _KMAC256_XOF:{	num = 256; kmac->xof = 1; rate = 136; break;}
	default:{		num = 128; kmac->xof = 0; rate = 168; break;}
    }

    switch (num) {
	case 128:{
	    if ((err = sha3_shake_128_init(&kmac->hs)) != NBSCrypto_OK) return err;
	    break;
	}
	case 256: {
	    if ((err = sha3_shake_256_init(&kmac->hs)) != NBSCrypto_OK) return err;
	    break;
	}

    }

    if ((err = _feed_bytepad_prefix(&kmac->hs, rate, &total)) != NBSCrypto_OK) return err;
    if ((err = _feed_encode_string(&kmac->hs, kmac_name, sizeof(kmac_name), &total)) != NBSCrypto_OK) return err;
    if ((err = _feed_encode_string(&kmac->hs, cust, custlen, &total)) != NBSCrypto_OK) return err;
    if ((err = _feed_bytepad_zero_fill(&kmac->hs, rate, total)) != NBSCrypto_OK) return err;

    if ((err = _feed_bytepad_prefix(&kmac->hs, rate, &total)) != NBSCrypto_OK) return err;
    if ((err = _feed_encode_string(&kmac->hs, key, keylen, &total)) != NBSCrypto_OK) return err;
    if ((err = _feed_bytepad_zero_fill(&kmac->hs, rate, total)) != NBSCrypto_OK) return err;

    return NBSCrypto_OK;
}

int kmac_process(const unsigned char *in, unsigned long inlen, kmac_state *kmac)
{
    if (inlen == 0) return NBSCrypto_OK;
    return sha3_process(&kmac->hs, in, inlen);
}

int kmac_done(unsigned char *out, unsigned long *outlen, kmac_state *kmac)
{
    int err;
    unsigned char enc[9];
    unsigned long enclen;
    unsigned long long L;

    L = kmac->xof ? 0 : (unsigned long long)(*outlen) * 8;
    enclen = _right_encode(L, enc);
    if ((err = sha3_process(&kmac->hs, enc, enclen)) != NBSCrypto_OK) return err;

    return sha3_shake_done_ex(&kmac->hs, out, *outlen, 0x04);
}
