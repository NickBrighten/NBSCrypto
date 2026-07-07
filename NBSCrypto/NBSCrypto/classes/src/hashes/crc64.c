//
//	crc64.c
//	Authors / Developers		: W. Wesley Peterson
//	Original			: 1961

//	Contributors
//	ECMA	-	ECMA-182 (December 1992)
//	MS	-	Microsoft Corporation (25 June 2021)
//	NVME	-	Don MacAskill (28 December 2023)
//	REDIS	-	Johann N. Löfflmann (16 November 2021)
//	WE	-	Wolfgang Ehrhardt (27 March 2012)
//	XZ	-	AUTOSAR (24 November 2022)
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor crc64_ECMA_182_desc =
{
    "crc64-ECMA-182",
    10120001,
    8,
    8,
    &crc64_ECMA_182_init,
    &crc64_process,
    &crc64_done,
    NULL
};

const struct hash_descriptor crc64_ISO_3309_desc =
{
    "crc64-ISO-3309",
    10120002,
    8,
    8,
    &crc64_ISO_3309_init,
    &crc64_process,
    &crc64_done,
    NULL
};

const struct hash_descriptor crc64_MS_desc =
{
    "crc64-MS",
    10120003,
    8,
    8,
    &crc64_MS_init,
    &crc64_process,
    &crc64_done,
    NULL
};

const struct hash_descriptor crc64_NVME_desc =
{
    "crc64-NVME",
    10120004,
    8,
    8,
    &crc64_NVME_init,
    &crc64_process,
    &crc64_done,
    NULL
};

const struct hash_descriptor crc64_REDIS_desc =
{
    "crc64-REDIS",
    10120005,
    8,
    8,
    &crc64_REDIS_init,
    &crc64_process,
    &crc64_done,
    NULL
};

const struct hash_descriptor crc64_WE_desc =
{
    "crc64-WE",
    10120006,
    8,
    8,
    &crc64_WE_init,
    &crc64_process,
    &crc64_done,
    NULL
};

const struct hash_descriptor crc64_XZ_desc =
{
    "crc64-XZ",
    10120007,
    8,
    8,
    &crc64_XZ_init,
    &crc64_process,
    &crc64_done,
    NULL
};




#pragma mark - DEFINES
static const unsigned long long b[]	= {
    0x0000000000000001, 0x8000000000000000
};

static const unsigned long long p1[]	= {
    0x000000000000001B, 0x259c84cba6426349, 0x42F0E1EBA9EA3693, 0xAD93D23594C935A9,
    0xAD93D23594C93659
};

static const unsigned long long p2[]	= {
    0xD800000000000000, 0x92C64265D32139A4, 0xC96C5795D7870F42, 0x95AC9329AC4BC9B5,
    0x9A6C9329AC4BC9B5
};

static const unsigned long long se[]	= {
    0x0000000000000000, 0xFFFFFFFFFFFFFFFF
};




#pragma mark - INLINE
static inline unsigned long long _upd(hash_state *hs, unsigned long long c, unsigned long long d)
{
    for(int i=0;i<sizeof(p1);i++){
	if (hs->crc64.p == p1[i]) {
	    if(hs->crc64.rev){
		c=c^d;
		for(int j=0;j<8;j++){
		    c=(c&b[0])?((c>>1)^p2[i]):(c>>1);
		}
	    }else{
		c=c^(d<<56);
		for(int j=0;j<8;j++){
		    c=(c&b[1])?((c<<1)^p1[i]):(c<<1);
		}
	    }
	}
    }

    return c;
}

static inline int _init(hash_state *hs, unsigned long long start, unsigned long long end, unsigned long long poly, int inverse, int reversed)
{
    hs->crc64.s = start;
    hs->crc64.e = end;
    hs->crc64.p = poly;
    hs->crc64.inv = inverse;
    hs->crc64.rev = reversed;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int crc64_ECMA_182_init(hash_state *hs){	return _init(hs, se[0], se[0], 0x42F0E1EBA9EA3693, 0, 0);}
int crc64_ISO_3309_init(hash_state *hs){	return _init(hs, se[1], se[1], 0x000000000000001B, 1, 1);}
int crc64_MS_init(hash_state *hs){		return _init(hs, se[1], se[0], 0x259c84cba6426349, 0, 1);}
int crc64_NVME_init(hash_state *hs){		return _init(hs, se[1], se[1], 0xAD93D23594C93659, 1, 1);}
int crc64_REDIS_init(hash_state *hs){		return _init(hs, se[0], se[0], 0xAD93D23594C935A9, 0, 1);}
int crc64_WE_init(hash_state *hs){		return _init(hs, se[1], se[0], 0x42F0E1EBA9EA3693, 1, 0);}
int crc64_XZ_init(hash_state *hs){		return _init(hs, se[1], se[1], 0x42F0E1EBA9EA3693, 1, 1);}

int crc64_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned long long c;
    c = hs->crc64.s;

    while (inlen--) {
	c = _upd(hs, c, *(in++));
    }

    hs->crc64.s = c;
    return NBSCrypto_OK;
}

int crc64_done(hash_state *hs, unsigned char *out)
{
    unsigned long long c;
    c = hs->crc64.s;

    if(hs->crc64.inv){
	c=~c;
    }

    if ((hs->crc64.e == se[0]) || (hs->crc64.e == se[1])) {
	out[0] = (unsigned char) (c >> 56);
	out[1] = (unsigned char) (c >> 48);
	out[2] = (unsigned char) (c >> 40);
	out[3] = (unsigned char) (c >> 32);
	out[4] = (unsigned char) (c >> 24);
	out[5] = (unsigned char) (c >> 16);
	out[6] = (unsigned char) (c >> 8);
	out[7] = (unsigned char) (c);
    } else {
	out[0] = (unsigned char) (c >> 56);
	out[1] = (unsigned char) (c >> 48);
	out[2] = (unsigned char) (c >> 40);
	out[3] = (unsigned char) (c >> 32);
	out[4] = (unsigned char) (c >> 24);
	out[5] = (unsigned char) (c >> 16);
	out[6] = (unsigned char) (c >> 8);
	out[7] = (unsigned char) ((c) - hs->crc64.e);
    }

    return NBSCrypto_OK;
}
