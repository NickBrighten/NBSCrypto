//
//  	xxhash.c
//	Authors / Developers		: Yann Collet
//	Last Modified (Original)	: 2023 (2012)
//

#include "nbs_crypto.h"
#include "xxhash.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor xxh_32_desc =
{
    "xxh-32",
    238,
    4,
    16,
    &xxh_32_init,
    &xxh_32_process,
    &xxh_32_done,
    NULL
};

const struct hash_descriptor xxh_64_desc =
{
    "xxh-64",
    239,
    8,
    32,
    &xxh_64_init,
    &xxh_64_process,
    &xxh_64_done,
    NULL
};

const struct hash_descriptor xxh3_64_desc =
{
    "xxh3-64",
    240,
    8,
    32,
    &xxh3_64_init,
    &xxh3_64_process,
    &xxh3_64_done,
    NULL
};

const struct hash_descriptor xxh3_128_desc =
{
    "xxh3-128",
    241,
    16,
    32,
    &xxh3_128_init,
    &xxh3_128_process,
    &xxh3_128_done,
    NULL
};




#pragma mark - FUNCTIONS
int xxh_32_init(hash_state *hs)
{
    zeromem((XXH32_state_t*)&hs->xxh.s, sizeof((XXH32_state_t*)hs->xxh.s));
    XXH32_reset((XXH32_state_t*)&hs->xxh.s, 0);
    return NBSCrypto_OK;
}

int xxh_32_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    XXH32_update((XXH32_state_t*)&hs->xxh.s, in, inlen);
    return NBSCrypto_OK;
}

int xxh_32_done(hash_state *hs, unsigned char *out)
{
    XXH32_canonicalFromHash((XXH32_canonical_t*)out, XXH32_digest((XXH32_state_t*)&hs->xxh.s));
    return NBSCrypto_OK;
}


int xxh_64_init(hash_state *hs)
{
    zeromem((XXH64_state_t*)&hs->xxh.s, sizeof((XXH64_state_t*)hs->xxh.s));
    XXH64_reset((XXH64_state_t*)&hs->xxh.s, 0);
    return NBSCrypto_OK;
}

int xxh_64_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    XXH64_update((XXH64_state_t*)&hs->xxh.s, in, inlen);
    return NBSCrypto_OK;
}

int xxh_64_done(hash_state *hs, unsigned char *out)
{
    XXH64_canonicalFromHash((XXH64_canonical_t*)out, XXH64_digest((XXH64_state_t*)&hs->xxh.s));
    return NBSCrypto_OK;
}

int xxh3_64_init(hash_state *hs)
{
    hs->xxh.s = (unsigned long long)XXH3_createState();
    zeromem((XXH3_state_t*)hs->xxh.s, sizeof((XXH3_state_t*)hs->xxh.s));
    XXH3_64bits_reset((XXH3_state_t*)&hs->xxh.s);
    return NBSCrypto_OK;
}

int xxh3_64_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    XXH3_64bits_update((XXH3_state_t*)&hs->xxh.s, in, inlen);
    return NBSCrypto_OK;
}

int xxh3_64_done(hash_state *hs, unsigned char *out)
{
    XXH64_canonicalFromHash((XXH64_canonical_t*)out, XXH3_64bits_digest((XXH3_state_t*)&hs->xxh.s));
    return NBSCrypto_OK;
}


int xxh3_128_init(hash_state *hs)
{
    hs->xxh.s = (unsigned long long)XXH3_createState();
    zeromem((XXH3_state_t*)&hs->xxh.s, sizeof((XXH3_state_t*)hs->xxh.s));
    XXH3_128bits_reset((XXH3_state_t*)&hs->xxh.s);
    return NBSCrypto_OK;
}

int xxh3_128_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    XXH3_128bits_update((XXH3_state_t*)&hs->xxh.s, in, inlen);
    return NBSCrypto_OK;
}

int xxh3_128_done(hash_state *hs, unsigned char *out)
{
    XXH128_canonicalFromHash((XXH128_canonical_t*)out, XXH3_128bits_digest((XXH3_state_t*)&hs->xxh.s));
    return NBSCrypto_OK;
}
