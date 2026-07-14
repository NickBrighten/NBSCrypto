//
//	sm3.c
//	Authors / Developers		: OSCCA
//	Last Modified (Original)	: December 17, 2010
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor sm3_desc =
{
    "sm3",
    227,
    32,
    64,
    &sm3_init,
    &sm3_process,
    &sm3_done,
    NULL
};




#pragma mark - DEFINES
#define BEG(n,b,i) {			\
    (n)=((unsigned)(b)[(i)]   << 24) |	\
	((unsigned)(b)[(i)+1] << 16) |	\
	((unsigned)(b)[(i)+2] <<  8) |	\
	((unsigned)(b)[(i)+3]);		\
}

#define BEP(n,b,i) {				\
    (b)[(i)    ] = (unsigned char) ((n) >> 24);	\
    (b)[(i) + 1] = (unsigned char) ((n) >> 16);	\
    (b)[(i) + 2] = (unsigned char) ((n) >>  8);	\
    (b)[(i) + 3] = (unsigned char) ((n));	\
}

#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x,y,z) ((x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ((~(x)) & (z)) )

#define SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x),17))
#define P1(x) ((x) ^ ROTL((x),15) ^ ROTL((x),23))


static unsigned char _sm3_padding[64] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};




#pragma mark - INLINE
static inline void _sm3_process_block(hash_state *hs, unsigned char data[64])
{
    unsigned A, B, C, D, E, F, G, H, SS1, SS2, T[64], TT1, TT2, W[68], W1[64];
    unsigned tmp1, tmp2, tmp3, tmp4, tmp5;
    int j;

    for(j= 0;j<16;j++){T[j] = 0x79CC4519;}
    for(j=16;j<64;j++){T[j] = 0x7A879D8A;}

    BEG(W[ 0], data,  0);
    BEG(W[ 1], data,  4);
    BEG(W[ 2], data,  8);
    BEG(W[ 3], data, 12);
    BEG(W[ 4], data, 16);
    BEG(W[ 5], data, 20);
    BEG(W[ 6], data, 24);
    BEG(W[ 7], data, 28);
    BEG(W[ 8], data, 32);
    BEG(W[ 9], data, 36);
    BEG(W[10], data, 40);
    BEG(W[11], data, 44);
    BEG(W[12], data, 48);
    BEG(W[13], data, 52);
    BEG(W[14], data, 56);
    BEG(W[15], data, 60);

    for(j=16;j<68;j++){
	tmp1 = W[j - 16] ^ W[j - 9];
	tmp2 = ROTL(W[j - 3], 15);
	tmp3 = tmp1 ^ tmp2;
	tmp4 = P1(tmp3);
	tmp5 = ROTL(W[j - 13], 7) ^ W[j - 6];
	W[j] = tmp4 ^ tmp5;
    }

    for(j=0;j<64;j++){W1[j] = W[j] ^ W[j + 4];}

    A = hs->sm3.state[0];
    B = hs->sm3.state[1];
    C = hs->sm3.state[2];
    D = hs->sm3.state[3];
    E = hs->sm3.state[4];
    F = hs->sm3.state[5];
    G = hs->sm3.state[6];
    H = hs->sm3.state[7];

    for(j=0;j<16;j++){
	SS1	= ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
	SS2	= SS1 ^ ROTL(A, 12);
	TT1	= FF0(A, B, C) + D + SS2 + W1[j];
	TT2	= GG0(E, F, G) + H + SS1 + W[j];
	D	= C;
	C	= ROTL(B, 9);
	B	= A;
	A	= TT1;
	H	= G;
	G	= ROTL(F, 19);
	F	= E;
	E	= P0(TT2);
    }

    for(j=16;j<64;j++){
	SS1	= ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
	SS2	= SS1 ^ ROTL(A, 12);
	TT1	= FF1(A, B, C) + D + SS2 + W1[j];
	TT2	= GG1(E, F, G) + H + SS1 + W[j];
	D	= C;
	C	= ROTL(B, 9);
	B	= A;
	A	= TT1;
	H	= G;
	G	= ROTL(F, 19);
	F	= E;
	E	= P0(TT2);
    }

    hs->sm3.state[0] ^= A;
    hs->sm3.state[1] ^= B;
    hs->sm3.state[2] ^= C;
    hs->sm3.state[3] ^= D;
    hs->sm3.state[4] ^= E;
    hs->sm3.state[5] ^= F;
    hs->sm3.state[6] ^= G;
    hs->sm3.state[7] ^= H;
}




#pragma mark - FUNCTIONS
int sm3_init(hash_state *hs)
{
    hs->sm3.total[0] = 0;
    hs->sm3.total[1] = 0;

    hs->sm3.state[0] = 0x7380166F;
    hs->sm3.state[1] = 0x4914B2B9;
    hs->sm3.state[2] = 0x172442D7;
    hs->sm3.state[3] = 0xDA8A0600;
    hs->sm3.state[4] = 0xA96F30BC;
    hs->sm3.state[5] = 0x163138AA;
    hs->sm3.state[6] = 0xE38DEE4D;
    hs->sm3.state[7] = 0xB0FB0E4E;

    return NBSCrypto_OK;
}

int sm3_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned left;
    int fill;

    if(inlen <= 0){return NBSCrypto_ERROR;}

    left = hs->sm3.total[0] & 0x3F;
    fill = 64 - left;

    hs->sm3.total[0] += inlen;
    hs->sm3.total[0] &= 0xFFFFFFFF;

    if(hs->sm3.total[0] < (unsigned) inlen){
	hs->sm3.total[1]++;
    }

    if(left && inlen >= fill){
	memcpy((void *)(hs->sm3.buf + left),(void *)in, fill);
	_sm3_process_block(hs, hs->sm3.buf);
	in	+= fill;
	inlen	-= fill;
	left	= 0;
    }

    while(inlen>=64){
	_sm3_process_block(hs, (unsigned char *)in);
	in	+= 64;
	inlen	-= 64;
    }

    if(inlen>0){memcpy((void *)(hs->sm3.buf + left), (void *)in, inlen);}

    return NBSCrypto_OK;
}

int sm3_done(hash_state *hs, unsigned char *out)
{
    unsigned high, last, low, padn;
    unsigned char msglen[8];

    high = (hs->sm3.total[0] >> 29) | (hs->sm3.total[1] <<  3);
    low  = (hs->sm3.total[0] <<  3);

    BEP(high, msglen, 0);
    BEP(low,  msglen, 4);

    last = hs->sm3.total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    sm3_process(hs, (const unsigned char *)_sm3_padding, padn);
    sm3_process(hs, msglen, 8);

    BEP(hs->sm3.state[0], out,  0);
    BEP(hs->sm3.state[1], out,  4);
    BEP(hs->sm3.state[2], out,  8);
    BEP(hs->sm3.state[3], out, 12);
    BEP(hs->sm3.state[4], out, 16);
    BEP(hs->sm3.state[5], out, 20);
    BEP(hs->sm3.state[6], out, 24);
    BEP(hs->sm3.state[7], out, 28);

    return NBSCrypto_OK;
}
