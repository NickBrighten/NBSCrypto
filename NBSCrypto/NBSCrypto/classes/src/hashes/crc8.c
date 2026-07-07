//
//	crc8.c
//	Authors / Developers		: W. Wesley Peterson
//	Last Modified (Original)	: 1961
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor crc8_AUTOSAR_desc =
{
    "crc8-AUTOSAR",
    10080001,
    1,
    1,
    &crc8_AUTOSAR_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_BLUETOOTH_desc =
{
    "crc8-BLUETOOTH",
    10080002,
    1,
    1,
    &crc8_BLUETOOTH_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_CDMA2000_desc =
{
    "crc8-CDMA2000",
    10080003,
    1,
    1,
    &crc8_CDMA2000_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_DARC_desc =
{
    "crc8-DARC",
    10080004,
    1,
    1,
    &crc8_DARC_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_DVB_S2_desc =
{
    "crc8-DVB-S2",
    10080005,
    1,
    1,
    &crc8_DVB_S2_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_GSM_A_desc =
{
    "crc8-GSM-A",
    10080006,
    1,
    1,
    &crc8_GSM_A_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_GSM_B_desc =
{
    "crc8-GSM-B",
    10080007,
    1,
    1,
    &crc8_GSM_B_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_HITAG_desc =
{
    "crc8-HITAG",
    10080008,
    1,
    1,
    &crc8_HITAG_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_ICODE_desc =
{
    "crc8-ICODE",
    10080009,
    1,
    1,
    &crc8_ICODE_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_ITU_desc =
{
    "crc8-ITU",
    10080010,
    1,
    1,
    &crc8_ITU_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_LTE_desc =
{
    "crc8-LTE",
    10080011,
    1,
    1,
    &crc8_LTE_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_MAXIM_desc =
{
    "crc8-MAXIM",
    10080012,
    1,
    1,
    &crc8_MAXIM_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_MIFARE_MAD_desc =
{
    "crc8-MIFARE-MAD",
    10080013,
    1,
    1,
    &crc8_MIFARE_MAD_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_NRSC_5_desc =
{
    "crc8-NRSC-5",
    10080014,
    1,
    1,
    &crc8_NRSC_5_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_OPENSAFETY_desc =
{
    "crc8-OPENSAFETY",
    10080015,
    1,
    1,
    &crc8_OPENSAFETY_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_ROHC_desc =
{
    "crc8-ROHC",
    10080016,
    1,
    1,
    &crc8_ROHC_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_SAE_J1850_desc =
{
    "crc8-SEA-J1850",
    10080017,
    1,
    1,
    &crc8_SAE_J1850_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_SMBUS_desc =
{
    "crc8-SMBUS",
    10080018,
    1,
    1,
    &crc8_SMBUS_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_TECH_3250_desc =
{
    "crc8-TECH-3250",
    10080019,
    1,
    1,
    &crc8_TECH_3250_init,
    &crc8_process,
    &crc8_done,
    NULL
};

const struct hash_descriptor crc8_WCDMA_desc =
{
    "crc8-WCDMA",
    10080020,
    1,
    1,
    &crc8_WCDMA_init,
    &crc8_process,
    &crc8_done,
    NULL
};




#pragma mark - DEFINES
static const unsigned b[]	= {
    0x01, 0x80
};

static const unsigned p1[]	= {
    0x07, 0x1D, 0x2F, 0x31, 0x39, 0x49, 0x9B, 0xA7,
    0xD5
};

static const unsigned p2[]	= {
    0xE0, 0xB8, 0xF4, 0x8C, 0x9C, 0x92, 0xD9, 0xE5,
    0xAB
};

static const unsigned se[]	= {
    0x00, 0x55, 0xC7, 0xFD, 0xFF
};




#pragma mark - INLINE
static inline unsigned _upd(hash_state *hs, unsigned c, unsigned d)
{
    for(int i=0;i<sizeof(p1);i++){
	if (hs->crc8.p == p1[i]) {
	    if(hs->crc8.rev){
		c=c^d;
		for(int j=0;j<8;j++){
		    c=(c&b[0])?((c>>1)^p2[i]):(c>>1);
		}
	    }else{
		c=c^d;
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
    hs->crc8.s = start;
    hs->crc8.e = end;
    hs->crc8.p = poly;
    hs->crc8.inv = inverse;
    hs->crc8.rev = reversed;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int crc8_AUTOSAR_init(hash_state *hs){		return _init(hs, se[4], se[4], 0x2F, 1, 0);}
int crc8_BLUETOOTH_init(hash_state *hs){	return _init(hs, se[0], se[0], 0xA7, 0, 1);}
int crc8_CDMA2000_init(hash_state *hs){		return _init(hs, se[4], se[0], 0x9B, 0, 0);}
int crc8_DARC_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x39, 0, 1);}
int crc8_DVB_S2_init(hash_state *hs){		return _init(hs, se[0], se[0], 0xD5, 0, 0);}
int crc8_GSM_A_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x1D, 0, 0);}
int crc8_GSM_B_init(hash_state *hs){		return _init(hs, se[0], se[4], 0x49, 1, 0);}
int crc8_HITAG_init(hash_state *hs){		return _init(hs, se[4], se[0], 0x1D, 0, 0);}
int crc8_ICODE_init(hash_state *hs){		return _init(hs, se[3], se[0], 0x1D, 0, 0);}
int crc8_ITU_init(hash_state *hs){		return _init(hs, se[0], se[1], 0x07, 0, 0);}
int crc8_LTE_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x9B, 0, 0);}
int crc8_MAXIM_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x31, 0, 1);}
int crc8_MIFARE_MAD_init(hash_state *hs){	return _init(hs, se[2], se[0], 0x1D, 0, 0);}
int crc8_NRSC_5_init(hash_state *hs){		return _init(hs, se[4], se[0], 0x31, 0, 0);}
int crc8_OPENSAFETY_init(hash_state *hs){	return _init(hs, se[0], se[0], 0x2F, 0, 0);}
int crc8_ROHC_init(hash_state *hs){		return _init(hs, se[4], se[0], 0x07, 0, 1);}
int crc8_SAE_J1850_init(hash_state *hs){	return _init(hs, se[4], se[4], 0x1D, 1, 0);}
int crc8_SMBUS_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x07, 0, 0);}
int crc8_TECH_3250_init(hash_state *hs){	return _init(hs, se[4], se[0], 0x1D, 0, 1);}
int crc8_WCDMA_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x9B, 0, 1);}

int crc8_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned c;
    c = hs->crc8.s;
    while (inlen--) {
	c = _upd(hs, c, *(in++));
    }
    hs->crc8.s = c;

    return NBSCrypto_OK;
}

int crc8_done(hash_state *hs, unsigned char *out)
{
    unsigned c;
    c = hs->crc8.s;

    if(hs->crc8.inv){
	c=~c;
    }

    if ((hs->crc8.e == 0x00) || (hs->crc8.e == 0xFF)) {
	out[0] = (unsigned char) (c);
    } else {
	out[0] = (unsigned char) ((c) - hs->crc8.e);
    }

    return NBSCrypto_OK;
}
