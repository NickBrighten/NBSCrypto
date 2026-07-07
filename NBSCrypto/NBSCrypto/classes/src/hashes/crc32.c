//
//	crc32.c
//	Authors / Developers		: W. Wesley Peterson
//	Last Modified (Original)	: 1961
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor crc32_AIXM_desc =
{
    "crc32-AIXM",
    10110001,
    4,
    4,
    &crc32_AIXM_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_AUTOSAR_desc =
{
    "crc32-AUTOSAR",
    10110002,
    4,
    4,
    &crc32_AUTOSAR_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_BASE91_D_desc =
{
    "crc32-BASE91-D",
    10110003,
    4,
    4,
    &crc32_BASE91_D_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_BZIP2_desc =
{
    "crc32-BZIP2",
    10110004,
    4,
    4,
    &crc32_BZIP2_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_CD_ROM_EDC_desc =
{
    "crc32-CD-ROM-EDC",
    10110005,
    4,
    4,
    &crc32_CD_ROM_EDC_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_CKSUM_desc =
{
    "crc32-CKSUM",
    10110006,
    4,
    4,
    &crc32_CKSUM_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_ISCSI_desc =
{
    "crc32-ISCSI",
    10110007,
    4,
    4,
    &crc32_ISCSI_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_ISO_HDLC_desc =
{
    "crc32-ISO-HDLC",
    10110008,
    4,
    4,
    &crc32_ISO_HDLC_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_JAMCRC_desc =
{
    "crc32-JAMCRC",
    10110009,
    4,
    4,
    &crc32_JAMCRC_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_MEF_desc =
{
    "crc32-MEF",
    10110010,
    4,
    4,
    &crc32_MEF_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_MPEG2_desc =
{
    "crc32-MPEG2",
    10110011,
    4,
    4,
    &crc32_MPEG2_init,
    &crc32_process,
    &crc32_done,
    NULL
};

const struct hash_descriptor crc32_XFER_desc =
{
    "crc32-XFER",
    10110012,
    4,
    4,
    &crc32_XFER_init,
    &crc32_process,
    &crc32_done,
    NULL
};




#pragma mark - DEFINES
static const unsigned b[]	= {
    0x00000001, 0x80000000
};

static const unsigned p1[]	= {
    0x000000AF, 0x04C11DB7, 0x1EDC6F41, 0x32583499, 0x741B8CD7, 0x8001801B, 0x814141AB, 0xA833982B,
    0xF4ACFB13
};

static const unsigned p2[]	= {
    0xF5000000, 0xEDB88320, 0x82F63B78, 0x992C1A4C, 0xEB31D82E, 0xD8018001, 0xD5828281, 0xD419CC15,
    0xC8DF352F
};

static const unsigned se[]	= {
    0x00000000, 0xFFFFFFFF
};




#pragma mark - INLINE
static inline unsigned _upd(hash_state *hs, unsigned c, unsigned d)
{
    for(int i=0;i<sizeof(p1);i++){
	if (hs->crc32.p == p1[i]) {
	    if(hs->crc32.rev){
		c=c^d;
		for(int j=0;j<8;j++){
		    c=(c&b[0])?((c>>1)^p2[i]):(c>>1);
		}
	    }else{
		c=c^(d<<24);
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
    hs->crc32.s = start;
    hs->crc32.e = end;
    hs->crc32.p = poly;
    hs->crc32.inv = inverse;
    hs->crc32.rev = reversed;

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int crc32_AIXM_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x814141AB, 0, 0);}
int crc32_AUTOSAR_init(hash_state *hs){		return _init(hs, se[1], se[1], 0xF4ACFB13, 1, 1);}
int crc32_BASE91_D_init(hash_state *hs){	return _init(hs, se[1], se[1], 0xA833982B, 1, 1);}
int crc32_BZIP2_init(hash_state *hs){		return _init(hs, se[1], se[1], 0x04C11DB7, 1, 0);}
int crc32_CD_ROM_EDC_init(hash_state *hs){	return _init(hs, se[0], se[0], 0x8001801B, 0, 1);}
int crc32_CKSUM_init(hash_state *hs){		return _init(hs, se[0], se[1], 0x04C11DB7, 1, 0);}
int crc32_ISCSI_init(hash_state *hs){		return _init(hs, se[1], se[1], 0x1EDC6F41, 1, 1);}
int crc32_ISO_HDLC_init(hash_state *hs){	return _init(hs, se[1], se[1], 0x04C11DB7, 1, 1);}
int crc32_JAMCRC_init(hash_state *hs){		return _init(hs, se[1], se[0], 0x04C11DB7, 0, 1);}
int crc32_MEF_init(hash_state *hs){		return _init(hs, se[1], se[0], 0x741B8CD7, 0, 1);}
int crc32_MPEG2_init(hash_state *hs){		return _init(hs, se[1], se[0], 0x04C11DB7, 0, 0);}
int crc32_XFER_init(hash_state *hs){		return _init(hs, se[0], se[0], 0x000000AF, 0, 0);}

int crc32_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    unsigned c;
    c = hs->crc32.s;

    while (inlen--) {
	c = _upd(hs, c, *(in++));
    }

    hs->crc32.s = c;
    return NBSCrypto_OK;
}

int crc32_done(hash_state *hs, unsigned char *out)
{
    unsigned c;
    c = hs->crc32.s;

    if(hs->crc32.inv){
	c=~c;
    }

    if ((hs->crc32.e == se[0]) || (hs->crc32.e == se[1])) {
	out[0] = (unsigned char) (c >> 24);
	out[1] = (unsigned char) (c >> 16);
	out[2] = (unsigned char) (c >> 8);
	out[3] = (unsigned char) (c);
    } else {
	out[0] = (unsigned char) (c >> 24);
	out[1] = (unsigned char) (c >> 16);
	out[2] = (unsigned char) (c >> 8);
	out[3] = (unsigned char) ((c) - hs->crc32.e);
    }

    return NBSCrypto_OK;
}
