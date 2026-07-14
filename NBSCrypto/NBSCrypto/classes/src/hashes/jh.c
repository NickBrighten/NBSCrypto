//
//	jh.c
//	Authors / Developers		: Hongjun Wu
//	Last Modified (Original)	: January 16, 2011
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor jh_224_desc =
{
    "jh-224",
    145,
    28,
    64,
    &jh_224_init,
    &jh_process,
    &jh_done,
    NULL
};

const struct hash_descriptor jh_256_desc =
{
    "jh-256",
    146,
    32,
    64,
    &jh_256_init,
    &jh_process,
    &jh_done,
    NULL
};

const struct hash_descriptor jh_384_desc =
{
    "jh-384",
    147,
    48,
    64,
    &jh_384_init,
    &jh_process,
    &jh_done,
    NULL
};

const struct hash_descriptor jh_512_desc =
{
    "jh-512",
    148,
    64,
    64,
    &jh_512_init,
    &jh_process,
    &jh_done,
    NULL
};




#pragma mark - DEFINES
#define L(a, b) {							\
    (b) ^= ( ( (a) << 1) ^ ( (a) >> 3) ^ (( (a) >> 2) & 2) ) & 0xf;	\
    (a) ^= ( ( (b) << 1) ^ ( (b) >> 3) ^ (( (b) >> 2) & 2) ) & 0xf;	\
}


const unsigned char jh_roundconstant_zero[64] =
{
    0x6,0xa,0x0,0x9,0xe,0x6,0x6,0x7,0xf,0x3,0xb,0xc,0xc,0x9,0x0,0x8,
    0xb,0x2,0xf,0xb,0x1,0x3,0x6,0x6,0xe,0xa,0x9,0x5,0x7,0xd,0x3,0xe,
    0x3,0xa,0xd,0xe,0xc,0x1,0x7,0x5,0x1,0x2,0x7,0x7,0x5,0x0,0x9,0x9,
    0xd,0xa,0x2,0xf,0x5,0x9,0x0,0xb,0x0,0x6,0x6,0x7,0x3,0x2,0x2,0xa
};

unsigned char jh_S[2][16] =
{
    { 9,  0, 4, 11, 13, 12, 3, 15,  1, 10, 2, 6,  7,  5,  8, 14},
    { 3, 12, 6, 13,  5,  7, 1,  9, 15,  2, 0, 4, 11, 10, 14,  8}
};




#pragma mark - INLINE
static inline void _jh_update_roundconstant(hash_state *hs)
{
    int i;
    unsigned char tem[64],t;

    for (i = 0; i < 64; i++)   tem[i] = jh_S[0][hs->jh.roundconstant[i]];

    for (i = 0; i < 64; i=i+2) L(tem[i], tem[i+1]);

    for ( i = 0; i < 64; i=i+4) {
	t = tem[i+2];
	tem[i+2] = tem[i+3];
	tem[i+3] = t;
    }

    for ( i = 0; i < 32; i=i+1) {
	hs->jh.roundconstant[i]    = tem[i<<1];
	hs->jh.roundconstant[i+32] = tem[(i<<1)+1];
    }

    for ( i = 32; i < 64; i=i+2 ) {
	t = hs->jh.roundconstant[i];
	hs->jh.roundconstant[i] = hs->jh.roundconstant[i+1];
	hs->jh.roundconstant[i+1] = t;
    }
}

static inline void _jh_R8(hash_state *hs)
{
    unsigned int i;
    unsigned char tem[256],t;
    unsigned char roundconstant_expanded[256];

    for (i = 0; i < 256; i++)  {
	roundconstant_expanded[i] = (hs->jh.roundconstant[i >> 2] >> (3 - (i & 3)) ) & 1;
    }

    for (i = 0; i < 256; i++) {
	tem[i] = jh_S[roundconstant_expanded[i]][hs->jh.A[i]];
    }

    for (i = 0; i < 256; i=i+2) L(tem[i], tem[i+1]);

    for ( i = 0; i < 256; i=i+4) {
	t = tem[i+2];
	tem[i+2] = tem[i+3];
	tem[i+3] = t;
    }

    for (i = 0; i < 128; i=i+1) {
	hs->jh.A[i] = tem[i<<1];
	hs->jh.A[i+128] = tem[(i<<1)+1];
    }

    for ( i = 128; i < 256; i=i+2) {
	t = hs->jh.A[i];
	hs->jh.A[i] = hs->jh.A[i+1];
	hs->jh.A[i+1] = t;
    }
}

static inline void _jh_E8_initialgroup(hash_state *hs)
{
    unsigned int i;
    unsigned char t0,t1,t2,t3;
    unsigned char tem[256];

    for (i = 0; i < 256; i++) {
	t0 = (hs->jh.H[i>>3] >> (7 - (i & 7)) ) & 1;
	t1 = (hs->jh.H[(i+256)>>3] >> (7 - (i & 7)) ) & 1;
	t2 = (hs->jh.H[(i+ 512 )>>3] >> (7 - (i & 7)) ) & 1;
	t3 = (hs->jh.H[(i+ 768 )>>3] >> (7 - (i & 7)) ) & 1;
	tem[i] = (t0 << 3) | (t1 << 2) | (t2 << 1) | (t3 << 0);
    }

    for (i = 0; i < 128; i++) {
	hs->jh.A[i << 1] = tem[i];
	hs->jh.A[(i << 1)+1] = tem[i+128];
    }
}

static inline void _jh_E8_finaldegroup(hash_state *hs)
{
    unsigned int i;
    unsigned char t0,t1,t2,t3;
    unsigned char tem[256];

    for (i = 0; i < 128; i++) {
	tem[i] = hs->jh.A[i << 1];
	tem[i+128] = hs->jh.A[(i << 1)+1];
    }

    for (i = 0; i < 128; i++) hs->jh.H[i] = 0;

    for (i = 0; i < 256; i++) {
	t0 = (tem[i] >> 3) & 1;
	t1 = (tem[i] >> 2) & 1;
	t2 = (tem[i] >> 1) & 1;
	t3 = (tem[i] >> 0) & 1;

	hs->jh.H[i>>3] |= t0 << (7 - (i & 7));
	hs->jh.H[(i + 256)>>3] |= t1 << (7 - (i & 7));
	hs->jh.H[(i + 512)>>3] |= t2 << (7 - (i & 7));
	hs->jh.H[(i + 768)>>3] |= t3 << (7 - (i & 7));
    }
}

static inline void _jh_E8(hash_state *hs)
{
    unsigned int i;

    for (i = 0; i < 64; i++) hs->jh.roundconstant[i] = jh_roundconstant_zero[i];

    _jh_E8_initialgroup(hs);

    for (i = 0; i < 42; i++) {
	_jh_R8(hs);
	_jh_update_roundconstant(hs);
    }

    _jh_E8_finaldegroup(hs);
}

static inline void _jh_F8(hash_state *hs)
{
    unsigned int i;

    for (i = 0; i < 64; i++) hs->jh.H[i] ^= hs->jh.buffer[i];

    _jh_E8(hs);

    for (i = 0; i < 64; i++) hs->jh.H[i+64] ^= hs->jh.buffer[i];
}

static inline int _jh_init(hash_state *hs, int len)
{
    unsigned int i;

    hs->jh.databitlen = 0;
    hs->jh.datasize_in_buffer = 0;

    hs->jh.hashbitlen = len;

    for (i = 0; i <  64; i++) hs->jh.buffer[i] = 0;
    for (i = 0; i < 128; i++) hs->jh.H[i] = 0;

    hs->jh.H[1] = len & 0xff;
    hs->jh.H[0] = (len >> 8) & 0xff;

    _jh_F8(hs);

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int jh_224_init(hash_state *hs){return _jh_init(hs, 224);}
int jh_256_init(hash_state *hs){return _jh_init(hs, 256);}
int jh_384_init(hash_state *hs){return _jh_init(hs, 384);}
int jh_512_init(hash_state *hs){return _jh_init(hs, 512);}

int jh_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long index;
    unsigned long ilen = inlen*8;

    hs->jh.databitlen += ilen;
    index = 0;

    if ( (hs->jh.datasize_in_buffer > 0 ) && (( hs->jh.datasize_in_buffer + ilen) < 512)  ) {
	if ( (ilen & 7) == 0 ) {
	    memcpy(hs->jh.buffer + (hs->jh.datasize_in_buffer >> 3), in, 64-(hs->jh.datasize_in_buffer >> 3)) ;
	}
	else memcpy(hs->jh.buffer + (hs->jh.datasize_in_buffer >> 3), in, 64-(hs->jh.datasize_in_buffer >> 3)+1) ;
	hs->jh.datasize_in_buffer += ilen;
	ilen = 0;
    }

    if ( (hs->jh.datasize_in_buffer > 0 ) && (( hs->jh.datasize_in_buffer + ilen) >= 512)  ) {
	memcpy( hs->jh.buffer + (hs->jh.datasize_in_buffer >> 3), in, 64-(hs->jh.datasize_in_buffer >> 3) ) ;
	index = (unsigned long)(64-(hs->jh.datasize_in_buffer >> 3));
	ilen = (unsigned long)(ilen - (512 - hs->jh.datasize_in_buffer));
	_jh_F8(hs);
	hs->jh.datasize_in_buffer = 0;
    }

    for ( ; ilen >= 512; index = index+64, ilen = ilen - 512) {
	memcpy(hs->jh.buffer, in+index, 64);
	_jh_F8(hs);
    }

    if ( ilen > 0) {
	if ((ilen & 7) == 0)
	    memcpy(hs->jh.buffer, in+index, (ilen & 0x1ff) >> 3);
	else
	    memcpy(hs->jh.buffer, in+index, ((ilen & 0x1ff) >> 3)+1);
	hs->jh.datasize_in_buffer = ilen;
    }

    return NBSCrypto_OK;
}

int jh_done(hash_state *hs, unsigned char *out)
{
    unsigned int i;

    if ( (hs->jh.databitlen & 0x1ff) == 0) {
	for (i = 0; i < 64; i++) hs->jh.buffer[i] = 0;
	hs->jh.buffer[0] = 0x80;
	hs->jh.buffer[63] =  hs->jh.databitlen & 0xff;
	hs->jh.buffer[62] = (hs->jh.databitlen >>  8) & 0xff;
	hs->jh.buffer[61] = (hs->jh.databitlen >> 16) & 0xff;
	hs->jh.buffer[60] = (hs->jh.databitlen >> 24) & 0xff;
	hs->jh.buffer[59] = (hs->jh.databitlen >> 32) & 0xff;
	hs->jh.buffer[58] = (hs->jh.databitlen >> 40) & 0xff;
	hs->jh.buffer[57] = (hs->jh.databitlen >> 48) & 0xff;
	hs->jh.buffer[56] = (hs->jh.databitlen >> 56) & 0xff;
	_jh_F8(hs);
    }
    else {
	if ( (hs->jh.datasize_in_buffer & 7) == 0)
	    for (i = (hs->jh.databitlen & 0x1ff) >> 3; i < 64; i++)  hs->jh.buffer[i] = 0;
	else
	    for (i = ((hs->jh.databitlen & 0x1ff) >> 3)+1; i < 64; i++)  hs->jh.buffer[i] = 0;

	hs->jh.buffer[((hs->jh.databitlen & 0x1ff) >> 3)] |= 1 << (7- (hs->jh.databitlen & 7));
	_jh_F8(hs);
	for (i = 0; i < 64; i++) hs->jh.buffer[i] = 0;
	hs->jh.buffer[63] = hs->jh.databitlen & 0xff;
	hs->jh.buffer[62] = (hs->jh.databitlen >>  8) & 0xff;
	hs->jh.buffer[61] = (hs->jh.databitlen >> 16) & 0xff;
	hs->jh.buffer[60] = (hs->jh.databitlen >> 24) & 0xff;
	hs->jh.buffer[59] = (hs->jh.databitlen >> 32) & 0xff;
	hs->jh.buffer[58] = (hs->jh.databitlen >> 40) & 0xff;
	hs->jh.buffer[57] = (hs->jh.databitlen >> 48) & 0xff;
	hs->jh.buffer[56] = (hs->jh.databitlen >> 56) & 0xff;
	_jh_F8(hs);
    }

    switch (hs->jh.hashbitlen) {
	case 224:  memcpy(out,hs->jh.H + 100, 28);  break;
	case 256:  memcpy(out,hs->jh.H +  96, 32);  break;
	case 384:  memcpy(out,hs->jh.H +  80, 48);  break;
	case 512:  memcpy(out,hs->jh.H +  64, 64);  break;
    }

    return NBSCrypto_OK;
}
