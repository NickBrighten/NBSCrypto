//
//	crc24.c
//	Authors / Developers		: W. Wesley Peterson
//	Last Modified (Original)	: 1961
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor crc24_BLE_desc =
{
    "crc24-BLE",
    10100001,
    3,
    3,
    &crc24_BLE_init,
    &crc24_process,
    &crc24_done,
    NULL
};

const struct hash_descriptor crc24_FLEXRAY_A_desc =
{
    "crc24-FLEXRAY-A",
    10100002,
    3,
    3,
    &crc24_FLEXRAY_A_init,
    &crc24_process,
    &crc24_done,
    NULL
};

const struct hash_descriptor crc24_FLEXRAY_B_desc =
{
    "crc24-FLEXRAY-B",
    10100003,
    3,
    3,
    &crc24_FLEXRAY_B_init,
    &crc24_process,
    &crc24_done,
    NULL
};

const struct hash_descriptor crc24_INTERLAKEN_desc =
{
    "crc24-INTERLAKEN",
    10100004,
    3,
    3,
    &crc24_INTERLAKEN_init,
    &crc24_process,
    &crc24_done,
    NULL
};

const struct hash_descriptor crc24_LTE_A_desc =
{
    "crc24-LTE-A",
    10100005,
    3,
    3,
    &crc24_LTE_A_init,
    &crc24_process,
    &crc24_done,
    NULL
};

const struct hash_descriptor crc24_LTE_B_desc =
{
    "crc24-LTE-B",
    10100006,
    3,
    3,
    &crc24_LTE_B_init,
    &crc24_process,
    &crc24_done,
    NULL
};

const struct hash_descriptor crc24_OPENPGP_desc =
{
    "crc24-OPENPGP",
    10100007,
    3,
    3,
    &crc24_OPENPGP_init,
    &crc24_process,
    &crc24_done,
    NULL
};

const struct hash_descriptor crc24_OS_9_desc =
{
    "crc24-OS-9",
    10100008,
    3,
    3,
    &crc24_OS_9_init,
    &crc24_process,
    &crc24_done,
    NULL
};




#pragma mark - DEFINES
static const unsigned b[]	= {
    0x000001, 0x800000
};

static const unsigned p1[]	= {
    0x00065B, 0x328B63, 0x5D6DCB, 0x800063, 0x864CFB
};

static const unsigned p2[]	= {
    0xDA6000, 0xC6D14C, 0xD3B6BA, 0xC60001, 0xDF3261
};

static const unsigned se[]	= {
    0x000000, 0xAAAAAA, 0xABCDEF, 0xB704CE, 0xFEDCBA, 0xFFFFFF
};




#pragma mark - INLINE
static inline unsigned _upd(hash_state *hs, unsigned c, unsigned d)
{
    for(int i=0;i<sizeof(p1);i++){
	if (hs->crc24.p == p1[i]) {
	    if(hs->crc24.rev){
		c=(c^d);
		for(int j=0;j<8;j++){
		    c=(c&b[0])?((c>>1)^p2[i]):(c>>1);
		}
	    }else{
		c=(c^(d<<16));
		for(int j=0;j<8;j++){
		    c=(c&b[1])?((c<<1)^p1[i]):(c<<1);
		}
	    }
	}
    }

    return c;
}

static inline int _init(hash_state *hs, unsigned start, unsigned end, unsigned poly, int inverse, int reversed)
{
    hs->crc24.s = start;
    hs->crc24.e = end;
    hs->crc24.p = poly;
    hs->crc24.inv = inverse;
    hs->crc24.rev = reversed;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int crc24_BLE_init(hash_state *hs){		return _init(hs, se[1], se[0], 0x00065B, 0, 1);}
int crc24_FLEXRAY_A_init(hash_state *hs){	return _init(hs, se[4], se[0], 0x5D6DCB, 0, 0);}
int crc24_FLEXRAY_B_init(hash_state *hs){	return _init(hs, se[2], se[0], 0x5D6DCB, 0, 0);}
int crc24_INTERLAKEN_init(hash_state *hs){	return _init(hs, se[5], se[5], 0x328B63, 1, 0);}
int crc24_LTE_A_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x864CFB, 0, 0);}
int crc24_LTE_B_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x800063, 0, 0);}
int crc24_OPENPGP_init(hash_state *hs){		return _init(hs, se[3], se[0], 0x864CFB, 0, 0);}
int crc24_OS_9_init(hash_state *hs){		return _init(hs, se[5], se[5], 0x800063, 1, 0);}

int crc24_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned c;
    c = hs->crc24.s;
    while (inlen--) {
	c = _upd(hs, c, *(in++));
    }
    hs->crc24.s = c;

    return NBSCrypto_OK;
}

int crc24_done(hash_state *hs, unsigned char *out)
{
    unsigned c;
    c = hs->crc24.s;

    if(hs->crc24.inv){
	c=~c;
    }

    if ((hs->crc24.e == se[0]) || (hs->crc24.e == se[5])) {
	out[0] = (unsigned char) (c >> 16);
	out[1] = (unsigned char) (c >> 8);
	out[2] = (unsigned char) (c);
    } else {
	out[0] = (unsigned char) (c >> 16);
	out[1] = (unsigned char) (c >> 8);
	out[2] = (unsigned char) ((c) - hs->crc24.e);
    }

    return NBSCrypto_OK;
}
