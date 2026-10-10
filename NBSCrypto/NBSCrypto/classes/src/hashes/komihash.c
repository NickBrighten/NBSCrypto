//
//	komihash.c
//	Authors / Developers		: Aleksey Vaneev
//	Last Modified (Original)	: 2025 (2021)
//

#include "nbs_crypto.h"
#include "komihash.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor komihash_desc =
{
    "komihash",
    156,
    8,
    16,
    &komihash_init,
    &komihash_process,
    &komihash_done,
    NULL
};




#pragma mark - FUNCTIONS
int komihash_init(hash_state *hs)
{
    komihash_stream_init((komihash_stream_t*)&hs->komihash, 123);
    return NBSCrypto_OK;
}

int komihash_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    komihash_stream_update((komihash_stream_t*)&hs->komihash, in, inlen);
    return NBSCrypto_OK;
}

int komihash_done(hash_state *hs, unsigned char *out)
{
    unsigned long long r = komihash_stream_final((komihash_stream_t*)&hs->komihash);

    out[7] = ((r >>  0) & 0xff);
    out[6] = ((r >>  8) & 0xff);
    out[5] = ((r >> 16) & 0xff);
    out[4] = ((r >> 24) & 0xff);
    out[3] = ((r >> 32) & 0xff);
    out[2] = ((r >> 40) & 0xff);
    out[1] = ((r >> 48) & 0xff);
    out[0] = ((r >> 56) & 0xff);

    return NBSCrypto_OK;
}
