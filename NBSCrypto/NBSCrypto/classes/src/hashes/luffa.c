//
//	luffa.c
//	Authors / Developers		: Hisayoshi Sato, Dai Watanabe
//	Last Modified (Original)	: October 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor luffa_224_desc =
{
    "luffa-224",
    163,
    28,
    32,
    &luffa_224_init,
    &luffa_process,
    &luffa_done,
    NULL
};

const struct hash_descriptor luffa_256_desc =
{
    "luffa-256",
    164,
    32,
    32,
    &luffa_256_init,
    &luffa_process,
    &luffa_done,
    NULL
};

const struct hash_descriptor luffa_384_desc =
{
    "luffa-384",
    165,
    48,
    32,
    &luffa_384_init,
    &luffa_process,
    &luffa_done,
    NULL
};

const struct hash_descriptor luffa_512_desc =
{
    "luffa-512",
    166,
    64,
    32,
    &luffa_512_init,
    &luffa_process,
    &luffa_done,
    NULL
};




#pragma mark - DEFINES

#define BYTES_SWAP32(x) ((x << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | (x >> 24))
#define BYTES_SWAP256(x) {					\
    int _i = 8; while(_i--){x[_i] = BYTES_SWAP32(x[_i]);}	\
}

#define DIGEST_BIT_LEN_224 224
#define DIGEST_BIT_LEN_256 256
#define DIGEST_BIT_LEN_384 384
#define DIGEST_BIT_LEN_512 512

#define LIMIT_224 64
#define LIMIT_256 64
#define LIMIT_384 128
#define LIMIT_512 128

#define MSG_BLOCK_BIT_LEN 256
#define MSG_BLOCK_BYTE_LEN (MSG_BLOCK_BIT_LEN >> 3)

#define WIDTH_224 3
#define WIDTH_256 3
#define WIDTH_384 4
#define WIDTH_512 5

const unsigned int CNS[10] = {
    0x181cca53,0x380cde06,0x5b6f0876,0xf16f8594,0x7e106ce9,
    0x38979cb0,0xbb62f364,0x92e93c29,0x9a025047,0xcff2a940
};

const unsigned int IV[40] = {
    0x6d251e69,0x44b051e0,0x4eaa6fb4,0xdbf78465,0x6e292011,0x90152df4,0xee058139,0xdef610bb,
    0xc3b44b95,0xd9d2f256,0x70eee9a0,0xde099fa3,0x5d9b0557,0x8fc944b3,0xcf1ccf0e,0x746cd581,
    0xf7efc89d,0x5dba5781,0x04016ce5,0xad659c05,0x0306194f,0x666d1836,0x24aa230a,0x8b264ae7,
    0x858075d5,0x36d79cce,0xe571f7d7,0x204b1f67,0x35870c6a,0x57e9e923,0x14bcb808,0x7cde72ce,
    0x6c68e9be,0x5ec41e22,0xc825b7c7,0xaffb4363,0xf5df3999,0x0fc688f1,0xb07224cc,0x03e86cea
};




#pragma mark - INLINE
static inline void _addconstant(unsigned int *a, unsigned int *cns)
{
    a[0] ^= cns[0];
    a[4] ^= cns[1];
}

static inline void _genconstant(unsigned int *c, unsigned int *cns)
{
    if(c[0]>>31) {
	c[0] = (c[0]<<1) ^ (c[1]>>31) ^ 0xc4d6496c;
	c[1] = (c[1]<<1) ^ 0x55c61c8d;
    } else {
	c[0] = (c[0]<<1) ^ (c[1]>>31);
	c[1] <<= 1;
    }
    cns[0] = c[0];
    c[0] = c[1];
    c[1] = cns[0];
    if(c[0]>>31) {
	c[0] = (c[0]<<1) ^ (c[1]>>31) ^ 0xc4d6496c;
	c[1] = (c[1]<<1) ^ 0x55c61c8d;
    } else {
	c[0] = (c[0]<<1) ^ (c[1]>>31);
	c[1] <<= 1;
    }
    cns[1] = c[0];
    c[0] = c[1];
    c[1] = cns[1];
}

static inline void _mult2(unsigned int a[8])
{
    unsigned int tmp;
    tmp = a[7];
    a[7] = a[6];
    a[6] = a[5];
    a[5] = a[4];
    a[4] = a[3] ^ tmp;
    a[3] = a[2] ^ tmp;
    a[2] = a[1];
    a[1] = a[0] ^ tmp;
    a[0] = tmp;
}

static inline void _mi(hash_state *hs)
{
    unsigned int t[40];
    int i, j;

    for (i = 0; i < 8; i++){
	t[i]=0;
	for(j = 0; j < hs->luffa.width; j++){
	    t[i] ^= hs->luffa.chainv[i+8*j];
	}
    }
    _mult2(t);

    for(j=0; j < hs->luffa.width; j++) {
	for(i=0;i<8;i++) {
	    hs->luffa.chainv[i+8*j] ^= t[i];
	}
    }

    if(hs->luffa.width>=5)
    {
	for(j=0;j<hs->luffa.width;j++) {
	    for(i=0;i<8;i++) t[i+8*j] = hs->luffa.chainv[i+8*j];
	    _mult2(&hs->luffa.chainv[8*j]);
	}
	for(j=0;j<hs->luffa.width;j++) {
	    for(i=0;i<8;i++) hs->luffa.chainv[8*j+i] ^= t[8*((j+1)%hs->luffa.width)+i];
	}
    }

    if(hs->luffa.width>=4)
    {
	for(j=0;j<hs->luffa.width;j++) {
	    for(i=0;i<8;i++) t[i+8*j] = hs->luffa.chainv[i+8*j];
	    _mult2(&hs->luffa.chainv[8*j]);
	}
	for(j=0;j<hs->luffa.width;j++) {
	    for(i=0;i<8;i++) hs->luffa.chainv[8*j+i] ^= t[8*((j-1+hs->luffa.width)%hs->luffa.width)+i];
	}
    }

    for (j = 0; j < hs->luffa.width; j++){
	for (i = 0; i < 8; i++){
	    hs->luffa.chainv[i+8*j] ^= hs->luffa.buffer[i];
	}

	_mult2(hs->luffa.buffer);
    }
}

static inline void _mixword(unsigned int *a)
{
    a[4] ^= a[0];
    a[0]  = (a[0]<< 2) | (a[0]>>(32-2));
    a[0] ^= a[4];
    a[4]  = (a[4]<<14) | (a[4]>>(32-14));
    a[4] ^= a[0];
    a[0]  = (a[0]<<10) | (a[0]>>(32-10));
    a[0] ^= a[4];
    a[4]  = (a[4]<< 1) | (a[4]>>(32-1));
}

static inline void _subcrumb(unsigned int *a)
{
    unsigned int tmp;
    tmp   = a[0];
    a[2] ^= a[1];
    a[0] &= a[1];
    a[0] ^= a[2];
    a[1]  = ~a[1];
    a[2] |= tmp;
    a[2] ^= a[3];
    tmp  ^= a[0];
    a[3] &= a[0];
    a[3] ^= a[1];
    tmp   = ~tmp;
    a[1] |= a[2];
    tmp  ^= a[1];
    a[0] ^= a[3];
    a[1] &= a[2];
    a[1] ^= a[3];
    a[2]  = a[3];
    a[3]  = tmp;
}

static inline void _step_part(unsigned int *a, unsigned int *c)
{
    unsigned int cns[2];
    _subcrumb(a  );
    _subcrumb(a+4);
    _mixword(a  );
    _mixword(a+1);
    _mixword(a+2);
    _mixword(a+3);
    _genconstant(c, cns);
    _addconstant(a, cns);
}

static inline void _step(hash_state *hs, unsigned int *c)
{
    int j;
    for(j=0;j<hs->luffa.width;j++) {
	_step_part(hs->luffa.chainv + 8*j, c+2*j  );
    }
}

static inline void _tweak(hash_state *hs)
{
    int i,j;
    for(j=0;j<hs->luffa.width;j++) {
	for(i=4;i<8;i++) {
	    hs->luffa.chainv[8*j+i] = (hs->luffa.chainv[8*j+i]<<j) | (hs->luffa.chainv[8*j+i]>>(32-j));
	}
    }
}

static inline void _rnd(hash_state *hs, unsigned int *c)
{
    int i;
    _mi(hs);
    _tweak(hs);
    for(i=0;i<8;i++) {
	_step(hs, c);
    }
}

static inline void _process_last_msgs(hash_state *hs)
{
    int i=0;
    unsigned int tail_len;
    unsigned int c[10];

    if(hs->luffa.hashbitlen == 224||hs->luffa.hashbitlen==256)
	tail_len = ((unsigned int) hs->luffa.bitlen[0])%MSG_BLOCK_BIT_LEN;
    else
	tail_len = ((unsigned int) hs->luffa.bitlen[1])%MSG_BLOCK_BIT_LEN;

    i= tail_len/8;

    if(!(tail_len%8)) {
	((unsigned char*)hs->luffa.buffer)[i] = 0x80;
    }else{
	((unsigned char*)hs->luffa.buffer)[i] &= (0xff<<(8-(tail_len%8)));
	((unsigned char*)hs->luffa.buffer)[i] |= (0x80>>(tail_len%8));
    }

    i++;

    /*
    for(i;i<32;i++){
	((unsigned char*)hs->luffa.buffer)[i] = 0;
    }
     */

    for(i=0;i<8;i++) {
	hs->luffa.buffer[i] = BYTES_SWAP32((hs->luffa.buffer[i]));
    }
    for(i=0;i<hs->luffa.width*2;i++) c[i] = CNS[i];
    _rnd(hs, c);

    /*    switch(state->limit) {
     case 1:
     if(tail_len < MSG_BLOCK_BIT_LEN - 64) {
     state->buffer[6] = (uint32) (state->bitlen[0]>>32);
     state->buffer[7] = (uint32) state->bitlen[0];
     for(i=0;i<state->width*2;i++) c[i] = CNS[i];
     rnd(state, c);
     }
     else {
     for(i=0;i<state->width*2;i++) c[i] = CNS[i];
     rnd(state, c);

     for(i=0;i<6;i++) state->buffer[i] = 0;
     state->buffer[6] = (uint32) (state->bitlen[0]>>32);
     state->buffer[7] = (uint32) state->bitlen[0];
     for(i=0;i<state->width*2;i++) c[i] = CNS[i];

     rnd(state, c);
     }
     break;
     case 2:
     if(tail_len < MSG_BLOCK_BIT_LEN - 2*64) {
     state->buffer[4] = (uint32) (state->bitlen[0]>>32);
     state->buffer[5] = (uint32) state->bitlen[0];
     state->buffer[6] = (uint32) (state->bitlen[1]>>32);
     state->buffer[7] = (uint32) state->bitlen[1];
     for(i=0;i<state->width*2;i++) c[i] = CNS[i];
     rnd(state, c);
     }
     else {
     for(i=0;i<state->width*2;i++) c[i] = CNS[i];
     rnd(state, c);

     for(i=0;i<4;i++) state->buffer[i] = 0;
     state->buffer[4] = (uint32) (state->bitlen[0]>>32);
     state->buffer[5] = (uint32) state->bitlen[0];
     state->buffer[6] = (uint32) (state->bitlen[1]>>32);
     state->buffer[7] = (uint32) state->bitlen[1];
     for(i=0;i<state->width*2;i++) c[i] = CNS[i];

     rnd(state, c);
     }
     break;
     default:
     break;
     }*/

}

static inline void _finalization(hash_state *hs, unsigned int *b)
{
    int i,j,branch=0;
    unsigned int c[10];

    switch(hs->luffa.hashbitlen) {
	case 224:
	case 256:
	    if(hs->luffa.bitlen[0]>=256) branch = 1;
	    break;

	case 384:
	case 512:
	    if(hs->luffa.bitlen[0]||(hs->luffa.bitlen[1]>=256)) branch = 1;
	    break;

	default:
	    break;
    }

    if(branch) {
	memset(hs->luffa.buffer, 0, MSG_BLOCK_BYTE_LEN);
	memcpy(c, CNS, hs->luffa.width*8);
	_rnd(hs, c);
    }

    switch(hs->luffa.hashbitlen) {
	case 224:
	    for(i=0;i<7;i++) {
		b[i] = 0;
		for(j=0;j<hs->luffa.width;j++) {
		    b[i] ^= hs->luffa.chainv[i+8*j];
		}
		b[i] = BYTES_SWAP32((b[i]));
	    }
	    break;

	case 256:
	case 384:
	case 512:
	    for(i=0;i<8;i++) {
		b[i] = 0;
		for(j=0;j<hs->luffa.width;j++) {
		    b[i] ^= hs->luffa.chainv[i+8*j];
		}
		b[i] = BYTES_SWAP32((b[i]));
	    }
	    if(hs->luffa.hashbitlen == 256) break;

	    memset(hs->luffa.buffer, 0, MSG_BLOCK_BYTE_LEN);
	    memcpy(c, CNS, hs->luffa.width*8);
	    _rnd(hs, c);

	    for(i=0;i<4;i++) {
		b[8+i] = 0;
		for(j=0;j<hs->luffa.width;j++) {
		    b[8+i] ^= hs->luffa.chainv[i+8*j];
		}
		b[8+i] = BYTES_SWAP32((b[8+i]));
	    }
	    if(hs->luffa.hashbitlen == 384) break;

	    for(i=4;i<8;i++) {
		b[8+i] = 0;
		for(j=0;j<hs->luffa.width;j++) {
		    b[8+i] ^= hs->luffa.chainv[i+8*j];
		}
		b[8+i] = BYTES_SWAP32((b[8+i]));
	    }
	    break;
	default:
	    break;
    }
}

static inline int _luffa_init(hash_state *hs, int hashbitlen)
{
    hs->luffa.hashbitlen = hashbitlen;

    switch(hashbitlen) {

	case 224:
	    hs->luffa.limit = LIMIT_224/64;
	    memset(hs->luffa.bitlen, 0, LIMIT_224/8);
	    hs->luffa.width = WIDTH_224;
	    memcpy(hs->luffa.chainv, IV, WIDTH_224*32);
	    break;

	case 256:
	    hs->luffa.limit = LIMIT_256/64;
	    memset(hs->luffa.bitlen, 0, LIMIT_256/8);
	    hs->luffa.width = WIDTH_256;
	    memcpy(hs->luffa.chainv, IV, WIDTH_256*32);
	    break;

	case 384:
	    hs->luffa.limit = LIMIT_384/64;
	    memset(hs->luffa.bitlen, 0, LIMIT_384/8);
	    hs->luffa.width = WIDTH_384;
	    memcpy(hs->luffa.chainv, IV, WIDTH_384*32);
	    break;

	case 512:
	    hs->luffa.limit = LIMIT_512/64;
	    memset(hs->luffa.bitlen, 0, LIMIT_512/8);
	    hs->luffa.width = WIDTH_512;
	    memcpy(hs->luffa.chainv, IV, WIDTH_512*32);
	    break;

	default:
	    return NBSCrypto_ERROR;
    }

    hs->luffa.rembitlen = 0;

    memset(hs->luffa.buffer, 0, MSG_BLOCK_BYTE_LEN);

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS

int luffa_224_init(hash_state *hs)
{
    return _luffa_init(hs, 224);
}

int luffa_256_init(hash_state *hs)
{
    return _luffa_init(hs, 256);
}

int luffa_384_init(hash_state *hs)
{
    return _luffa_init(hs, 384);
}

int luffa_512_init(hash_state *hs)
{
    return _luffa_init(hs, 512);
}

int luffa_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    int i, ret;
    unsigned char *p = (unsigned char*)hs->luffa.buffer;
    unsigned int cpylen;
    unsigned long len;
    unsigned int c[10];

    switch(hs->luffa.hashbitlen) {

	case 224:
	case 256:
	case 384:
	case 512:
	    if(hs->luffa.hashbitlen==224||hs->luffa.hashbitlen==256)
		hs->luffa.bitlen[0] += inlen;
	    else {
		if((hs->luffa.bitlen[1] += inlen) < inlen) {
		    hs->luffa.bitlen[0] +=1;
		}
	    }

	    if (hs->luffa.rembitlen + inlen >= MSG_BLOCK_BIT_LEN) {
		cpylen = MSG_BLOCK_BYTE_LEN - (hs->luffa.rembitlen >> 3);

		memcpy(p + (hs->luffa.rembitlen >> 3), in, cpylen);

		BYTES_SWAP256(hs->luffa.buffer);

		for(i=0;i<(hs->luffa.width*2);i++) c[i] = CNS[i];
		_rnd(hs, c);

		inlen -= (cpylen << 3);
		in += cpylen;
		hs->luffa.rembitlen = 0;

		while (inlen >= MSG_BLOCK_BIT_LEN) {
		    memcpy(p, in, MSG_BLOCK_BYTE_LEN);

		    BYTES_SWAP256(hs->luffa.buffer);

		    for(i=0;i<(hs->luffa.width*2);i++) c[i] = CNS[i];
		    _rnd(hs, c);

		    inlen -= MSG_BLOCK_BIT_LEN;
		    in += MSG_BLOCK_BYTE_LEN;
		}
	    }

	    if (inlen) {
		len = inlen >> 3;
		if (inlen % 8 != 0) {
		    len += 1;
		}

		memcpy(p + (hs->luffa.rembitlen >> 3), in, len);
		hs->luffa.rembitlen += inlen;
	    }

	    ret = NBSCrypto_OK;
	    break;

	default:
	    ret = NBSCrypto_ERROR;
	    break;
    }

    return ret;
}

int luffa_done(hash_state *hs, unsigned char *out)
{
    int ret;

    switch(hs->luffa.hashbitlen) {

	case 224:
	case 256:
	case 384:
	case 512:
	    _process_last_msgs(hs);
	    _finalization(hs, (unsigned int*) out);
	    ret = NBSCrypto_OK;
	    break;

	default:
	    ret = NBSCrypto_ERROR;
	    break;
    }

    return ret;
}
