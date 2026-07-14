//
//	crc16.c
//	Authors / Developers		: W. Wesley Peterson
//	Last Modified (Original)	: 1961
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor crc16_desc =
{
    "crc16",
    43,
    2,
    2,
    &crc16_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_CDMA2000_desc =
{
    "crc16-CDMA2000",
    44,
    2,
    2,
    &crc16_CDMA2000_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_CMS_desc =
{
    "crc16-CMS",
    45,
    2,
    2,
    &crc16_CMS_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_DDS110_desc =
{
    "crc16-DDS110",
    46,
    2,
    2,
    &crc16_DDS110_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_DECTR_desc =
{
    "crc16-DECTR",
    47,
    2,
    2,
    &crc16_DECTR_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_DECTX_desc =
{
    "crc16-DECTX",
    48,
    2,
    2,
    &crc16_DECTX_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_DNP_desc =
{
    "crc16-DNP",
    49,
    2,
    2,
    &crc16_DNP_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_EN13757_desc =
{
    "crc16-EN13757",
    50,
    2,
    2,
    &crc16_EN13757_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_GENIBUS_desc =
{
    "crc16-GENIBUS",
    51,
    2,
    2,
    &crc16_GENIBUS_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_GSM_desc =
{
    "crc16-GSM",
    52,
    2,
    2,
    &crc16_GSM_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_IBM3740_desc =
{
    "crc16-IBM3740",
    53,
    2,
    2,
    &crc16_IBM3740_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_IBMSDLC_desc =
{
    "crc16-IBMSDLC",
    54,
    2,
    2,
    &crc16_IBMSDLC_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_ISO_IEC_14443_3_A_desc =
{
    "crc16-ISO-IEC-14443-3-A",
    55,
    2,
    2,
    &crc16_ISO_IEC_14443_3_A_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_KERMIT_desc =
{
    "crc16-KERMIT",
    56,
    2,
    2,
    &crc16_KERMIT_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_LJ1200_desc =
{
    "crc16-LJ1200",
    57,
    2,
    2,
    &crc16_LJ1200_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_M17_desc =
{
    "crc16-M17",
    58,
    2,
    2,
    &crc16_M17_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_MAXIM_desc =
{
    "crc16-MAXIM",
    59,
    2,
    2,
    &crc16_MAXIM_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_MCRF4XX_desc =
{
    "crc16-MCRF4XX",
    60,
    2,
    2,
    &crc16_MCRF4XX_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_MODBUS_desc =
{
    "crc16-MODBUS",
    61,
    2,
    2,
    &crc16_MODBUS_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_NRSC5_desc =
{
    "crc16-NRSC5",
    62,
    2,
    2,
    &crc16_NRSC5_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_OPENSAFETY_A_desc =
{
    "crc16-OPENSAFETY-A",
    63,
    2,
    2,
    &crc16_OPENSAFETY_A_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_OPENSAFETY_B_desc =
{
    "crc16-OPENSAFETY-B",
    64,
    2,
    2,
    &crc16_OPENSAFETY_B_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_PROFIBUS_desc =
{
    "crc16-PROFIBUS",
    65,
    2,
    2,
    &crc16_PROFIBUS_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_RIELLO_desc =
{
    "crc16-RIELLO",
    66,
    2,
    2,
    &crc16_RIELLO_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_SPI_FUJITSU_desc =
{
    "crc16-SPI-FUJITSU",
    67,
    2,
    2,
    &crc16_SPI_FUJITSU_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_T10DIF_desc =
{
    "crc16-T10DIF",
    68,
    2,
    2,
    &crc16_T10DIF_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_TELEDISK_desc =
{
    "crc16-TELEDISK",
    69,
    2,
    2,
    &crc16_TELEDISK_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_TMS37157_desc =
{
    "crc16-TMS37157",
    70,
    2,
    2,
    &crc16_TMS37157_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_UMTS_desc =
{
    "crc16-UMTS",
    71,
    2,
    2,
    &crc16_UMTS_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_USB_desc =
{
    "crc16-USB",
    72,
    2,
    2,
    &crc16_USB_init,
    &crc16_process,
    &crc16_done,
    NULL
};

const struct hash_descriptor crc16_XMODEM_desc =
{
    "crc16-XMODEM",
    73,
    2,
    2,
    &crc16_XMODEM_init,
    &crc16_process,
    &crc16_done,
    NULL
};




#pragma mark - DEFINES
static const unsigned b[]	= {
    0x0001, 0x8000
};

static const unsigned p1[]	= {
    0x0589, 0x080B, 0x1021, 0x1DCF, 0x2F15, 0x3D65, 0x5935, 0x6F63,
    0x755B, 0x8005, 0x8BB7, 0xA02B, 0xA097, 0xC867
};

static const unsigned p2[]	= {
    0x91A0, 0xD010, 0x8408, 0xF3B8, 0xA8F4, 0xA6BC, 0xAC9A, 0x637B,
    0xDAAE, 0xA001, 0xEDD1, 0xD405, 0xE905, 0xE613
};

static const unsigned se[]	= {
    0x0000, 0x0001, 0x1D0F, 0x3791, 0x554D, 0x6363, 0x800D, 0xFFFF
};




#pragma mark - INLINE
static inline unsigned _upd(hash_state *hs, unsigned c, unsigned d)
{
    for(int i=0;i<sizeof(p1);i++){
	if (hs->crc16.p == p1[i]) {
	    if(hs->crc16.rev){
		c=(c^d);
		for(int j=0;j<8;j++){
		    c=(c&b[0])?((c>>1)^p2[i]):(c>>1);
		}
	    }else{
		c=(c^(d<<8));
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
    hs->crc16.s = start;
    hs->crc16.e = end;
    hs->crc16.p = poly;
    hs->crc16.inv = inverse;
    hs->crc16.rev = reversed;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int crc16_init(hash_state *hs){				return _init(hs, se[0], se[0], 0x8005, 0, 1);}
int crc16_CDMA2000_init(hash_state *hs){		return _init(hs, se[7], se[0], 0xC867, 0, 0);}
int crc16_CMS_init(hash_state *hs){			return _init(hs, se[7], se[0], 0x8005, 0, 0);}
int crc16_DDS110_init(hash_state *hs){			return _init(hs, se[6], se[0], 0x8005, 0, 0);}
int crc16_DECTR_init(hash_state *hs){			return _init(hs, se[0], se[1], 0x0589, 0, 0);}
int crc16_DECTX_init(hash_state *hs){			return _init(hs, se[0], se[0], 0x0589, 0, 0);}
int crc16_DNP_init(hash_state *hs){			return _init(hs, se[0], se[7], 0x3D65, 1, 1);}
int crc16_EN13757_init(hash_state *hs){			return _init(hs, se[0], se[7], 0x3D65, 1, 0);}
int crc16_GENIBUS_init(hash_state *hs){			return _init(hs, se[7], se[7], 0x1021, 1, 0);}
int crc16_GSM_init(hash_state *hs){			return _init(hs, se[0], se[7], 0x1021, 1, 0);}
int crc16_IBM3740_init(hash_state *hs){			return _init(hs, se[7], se[0], 0x1021, 0, 0);}
int crc16_IBMSDLC_init(hash_state *hs){			return _init(hs, se[7], se[7], 0x1021, 1, 1);}
int crc16_ISO_IEC_14443_3_A_init(hash_state *hs){	return _init(hs, se[5], se[0], 0x1021, 0, 1);}
int crc16_KERMIT_init(hash_state *hs){			return _init(hs, se[0], se[0], 0x1021, 0, 1);}
int crc16_LJ1200_init(hash_state *hs){			return _init(hs, se[0], se[0], 0x6F63, 0, 0);}
int crc16_M17_init(hash_state *hs){			return _init(hs, se[7], se[0], 0x5935, 0, 0);}
int crc16_MAXIM_init(hash_state *hs){			return _init(hs, se[0], se[7], 0x8005, 1, 1);}
int crc16_MCRF4XX_init(hash_state *hs){			return _init(hs, se[7], se[0], 0x1021, 0, 1);}
int crc16_MODBUS_init(hash_state *hs){			return _init(hs, se[7], se[0], 0x8005, 0, 1);}
int crc16_NRSC5_init(hash_state *hs){			return _init(hs, se[7], se[0], 0x080B, 0, 1);}
int crc16_OPENSAFETY_A_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x5935, 0, 0);}
int crc16_OPENSAFETY_B_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x755B, 0, 0);}
int crc16_PROFIBUS_init(hash_state *hs){		return _init(hs, se[7], se[7], 0x1DCF, 1, 0);}
int crc16_RIELLO_init(hash_state *hs){			return _init(hs, se[4], se[0], 0x1021, 0, 1);}
int crc16_SPI_FUJITSU_init(hash_state *hs){		return _init(hs, se[2], se[0], 0x1021, 0, 0);}
int crc16_T10DIF_init(hash_state *hs){			return _init(hs, se[0], se[0], 0x8BB7, 0, 0);}
int crc16_TELEDISK_init(hash_state *hs){		return _init(hs, se[0], se[0], 0xA097, 0, 0);}
int crc16_TMS37157_init(hash_state *hs){		return _init(hs, se[3], se[0], 0x1021, 0, 1);}
int crc16_UMTS_init(hash_state *hs){			return _init(hs, se[0], se[0], 0x8005, 0, 0);}
int crc16_USB_init(hash_state *hs){			return _init(hs, se[7], se[7], 0x8005, 1, 1);}
int crc16_XMODEM_init(hash_state *hs){			return _init(hs, se[0], se[0], 0x1021, 0, 0);}

int crc16_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned c;
    c = hs->crc16.s;
    while (inlen--) {
	c = _upd(hs, c, *(in++));
    }
    hs->crc16.s = c;

    return NBSCrypto_OK;
}

int crc16_done(hash_state *hs, unsigned char *out)
{
    unsigned c;
    c = hs->crc16.s;

    if(hs->crc16.inv){
	c=~c;
    }

    if ((hs->crc16.e == se[0]) || (hs->crc16.e == se[7])) {
	out[0] = (unsigned char) (c >> 8);
	out[1] = (unsigned char) (c);
    } else {
	out[0] = (unsigned char) (c >> 8);
	out[1] = (unsigned char) ((c) - hs->crc16.e);
    }

    return NBSCrypto_OK;
}
