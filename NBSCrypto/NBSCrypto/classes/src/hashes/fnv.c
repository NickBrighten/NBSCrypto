//
//	fnv.c
//	Authors / Developers		: Glenn Fowler, Landon Curt Noll, Phong Vo
//	Last Modified (Original)	: 1991
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor fnv1_32_desc =
{
    "fnv1-32",
    10153201,
    4,
    4,
    &fnv1_32_init,
    &fnv1_32_process,
    &fnv1_32_done,
    NULL
};

const struct hash_descriptor fnv1a_32_desc =
{
    "fnv1a-32",
    10153202,
    4,
    4,
    &fnv1_32_init,
    &fnv1a_32_process,
    &fnv1_32_done,
    NULL
};

const struct hash_descriptor fnv1_64_desc =
{
    "fnv1-64",
    10156401,
    8,
    8,
    &fnv1_64_init,
    &fnv1_64_process,
    &fnv1_64_done,
    NULL
};

const struct hash_descriptor fnv1a_64_desc =
{
    "fnv1a-64",
    10156402,
    8,
    8,
    &fnv1_64_init,
    &fnv1a_64_process,
    &fnv1_64_done,
    NULL
};




#pragma mark - INLINE
static inline unsigned _fnv132_compress(void *in, unsigned long len, unsigned out, int opt)
{
    unsigned char *bp = (unsigned char *)in;
    unsigned char *be = bp + len;

    if(opt==0){
	while(bp<be){
	    out *= 0x01000193;
	    out ^= (unsigned)*bp++;
	}
    }else{
	while(bp<be){
	    out ^= (unsigned)*bp++;
	    out *= 0x01000193;
	}
    }

    return out;
}

static inline unsigned long long _fnv164_compress(void *in, unsigned long len, unsigned long long out, int opt)
{
    unsigned char *bp = (unsigned char *)in;
    unsigned char *be = bp + len;

    if(opt==0){
	while(bp<be){
	    out *= 0x100000001b3ULL;
	    out ^= (unsigned long long)*bp++;
	}
    }else{
	while(bp<be){
	    out ^= (unsigned long long)*bp++;
	    out *= 0x100000001b3ULL;
	}
    }

    return out;
}




#pragma mark - FUNCTIONS
int fnv1_32_init(hash_state *hs)
{
    hs->fnv132.state = 0x811c9dc5;
    return NBSCrypto_OK;
}

int fnv1_64_init(hash_state *hs)
{
    hs->fnv164.state = 0xcbf29ce484222325ULL;
    return NBSCrypto_OK;
}

int fnv1_32_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    hs->fnv132.state = _fnv132_compress((void *)in, inlen, hs->fnv132.state, 0);
    return NBSCrypto_OK;
}

int fnv1_64_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    hs->fnv164.state = _fnv164_compress((void *)in, inlen, hs->fnv164.state, 0);
    return NBSCrypto_OK;
}

int fnv1a_32_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    hs->fnv132.state = _fnv132_compress((void *)in, inlen, hs->fnv132.state, 1);
    return NBSCrypto_OK;
}

int fnv1a_64_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    hs->fnv164.state = _fnv164_compress((void *)in, inlen, hs->fnv164.state, 1);
    return NBSCrypto_OK;
}

int fnv1_32_done(hash_state *hs, unsigned char *out)
{
    unsigned char *c = (unsigned char *) &hs->fnv132.state;

    for(int i=0;i<4;i++){
	out[i]=c[3-i];
    }

    return NBSCrypto_OK;
}

int fnv1_64_done(hash_state *hs, unsigned char *out)
{
    unsigned char *c = (unsigned char *) &hs->fnv164.state;

    for(int i=0;i<8;i++){
	out[i]=c[7-i];
    }

    return NBSCrypto_OK;
}
