//
//	joaat.c
//	Authors / Developers		: Bob Jenkins
//	Last Modified (Original)	: 1997
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor joaat_desc =
{
    "joaat",
    148,
    4,
    4,
    &joaat_init,
    &joaat_process,
    &joaat_done,
    NULL
};




#pragma mark - INLINE
static inline unsigned _joaat_compress(void *in, unsigned long len, unsigned out)
{
    unsigned char *input = (unsigned char *)in;

    for (int i=0; i<len;i++) {
	out += input[i];
	out += (out << 10);
	out ^= (out >> 6);
    }

    return out;
}




#pragma mark - FUNCTIONS
int joaat_init(hash_state *hs)
{
    hs->joaat.state = 0;

    return NBSCrypto_OK;
}

int joaat_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    hs->joaat.state = _joaat_compress((void *)in, inlen, hs->joaat.state);

    return NBSCrypto_OK;
}

int joaat_done(hash_state *hs, unsigned char *out)
{
    unsigned o = hs->joaat.state;
    o += (o << 3);
    o ^= (o >> 11);
    o += (o << 15);

    unsigned char *c = (unsigned char *) &o;

    for(int i=0;i<4;i++){
	out[i]=c[3-i];
    }

    hs->joaat.state = 0;

    return NBSCrypto_OK;
}
