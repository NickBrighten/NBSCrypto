//
//	nbs_hashes.h
//

#ifndef nbs_hashes_h
#define nbs_hashes_h


#pragma mark - HASH STRUCTS

struct adler32_state{
    unsigned short s[2];
};

struct blake2b_state{
    unsigned char buf[128];
    unsigned char last_node;
    unsigned long curlen;
    unsigned long outlen;
    unsigned long long h[8];
    unsigned long long t[2];
    unsigned long long f[2];
};

struct blake2s_state{
    unsigned h[8];
    unsigned t[2];
    unsigned f[2];
    unsigned char buf[64];
    unsigned char last_node;
    unsigned long curlen;
    unsigned long outlen;
};

struct chi_state{
    union {
	unsigned long long small[6];
	unsigned long long large[9];
	unsigned long long small32[2*6];
	unsigned long long large32[2*9];
    } hs_State;
    unsigned int hs_HashBitLen;
    unsigned int hs_MessageLen;
    unsigned int hs_DataLen;
    unsigned char hs_DataBuffer[128];
    unsigned long long hs_TotalLenLow;
    unsigned long long hs_TotalLenHigh;
};

struct crc8_state{
    int inv, rev;
    unsigned s, e, p;
};

struct crc16_state{
    int inv, rev;
    unsigned s, e, p;
};

struct crc24_state{
    int inv, rev;
    unsigned s, e, p;
};

struct crc32_state{
    int inv, rev;
    unsigned s, e, p;
};

struct crc64_state{
    int inv, rev;
    unsigned long long s, e, p;
};

struct echo_state{
    int cv_blocks;
    int inlen;
    int outlen;
    unsigned char SALT[128];
    unsigned long long counter;
    unsigned long long CV[8*2];
    unsigned long long state[16*2];
};

struct fnv132_state{
    unsigned state;
};

struct fnv164_state{
    unsigned long long state;
};

struct gost_state{
    const unsigned (*t)[4][256];
    unsigned s[16];
    unsigned char len, buf[32];
    unsigned long cnt[2];
};

struct groestl_state{
    int buf_ptr;
    int bits_in_last_byte;
    int hashbitlen;
    int size;
    unsigned char *buffer;
    unsigned long long *chaining __attribute__((aligned(16)));
    unsigned long long block_counter;
};

struct hamsi_state{
    int hashbitlen;
    unsigned long leftbits;
    int cvsize;
    int ROUNDS;
    int PFROUNDS;
    unsigned char leftdata[8];
    unsigned int state[16];
    unsigned int counter;
};

struct haval_state{
    char passes;
    short output;
    unsigned state[8];
    unsigned count[2];
    unsigned char buffer[128];
    void (*transform)(unsigned state[8], const unsigned char block[128], char passes);
};

struct jh_state{
    int hashbitlen;
    unsigned char H[128];
    unsigned char A[256];
    unsigned char roundconstant[64];
    unsigned char buffer[64];
    unsigned long long databitlen;
    unsigned long long datasize_in_buffer;
};

struct joaat_state{
    unsigned state;
};

struct lane_state{
    int hashbitlen;
    unsigned char buffer[128];
    unsigned char hash[64];
    unsigned long databitcount;
};

struct lesamnta256_state{
    int hashbitlen;
    unsigned int buffer[8];
    unsigned int hash[8];
    unsigned int rembitlen;
    unsigned long long bitlen[1];
};

struct lesamnta512_state{
    int hashbitlen;
    unsigned int rembitlen;
    unsigned long long bitlen[2];
    unsigned long long buffer[8];
    unsigned long long hash[8];
};

struct luffa_state{
    int hashbitlen;
    int width;
    int limit;
    unsigned long long bitlen[2];
    unsigned int rembitlen;
    unsigned int buffer[8];
    unsigned int chainv[40];
};

struct md2_state{
    unsigned char chksum[16], X[48], buf[16];
    unsigned long curlen;
};

struct md4_state{
    unsigned state[4], curlen;
    unsigned char buf[64];
    unsigned long long length;
};

struct md5_state{
    unsigned state[4], curlen;
    unsigned char buf[64];
    unsigned long long length;
};

struct murmur3a_state{
    unsigned len;
    unsigned h;
    unsigned carry;
};

struct murmur3c_state{
    unsigned len;
    unsigned h[4];
    unsigned carry[4];
};

struct murmur3f_state{
    unsigned len;
    unsigned long long h[4];
    unsigned long long carry[4];
};

struct ripemd128_state{
    unsigned state[4], curlen;
    unsigned char buf[64];
    unsigned long long length;
};

struct ripemd160_state{
    unsigned state[5], curlen;
    unsigned char buf[64];
    unsigned long long length;
};

struct ripemd256_state{
    unsigned state[8], curlen;
    unsigned char buf[64];
    unsigned long long length;
};

struct ripemd320_state{
    unsigned state[10], curlen;
    unsigned char buf[64];
    unsigned long long length;
};

struct sha1_state{
    unsigned state[5], curlen;
    unsigned long long length;
    unsigned char buf[64];
};

struct sha256_state{
    unsigned state[8], curlen;
    unsigned long long length;
    unsigned char buf[64];
};

struct sha512_state{
    unsigned long long length, state[8];
    unsigned long curlen;
    unsigned char buf[128];
};

struct sha3_state{
    unsigned char sb[25*8];
    unsigned long long saved;
    unsigned long long s[25];
    unsigned short byte_index;
    unsigned short capacity_words;
    unsigned short word_index;
    unsigned short xof_flag;
};

struct shabal_state{
    int hashbitlen;
    unsigned char buffer[16*4];
    size_t buffer_ptr;
    unsigned A[12];
    unsigned B[16];
    unsigned C[16];
    unsigned last_byte_significant_bits;
    unsigned Whigh, Wlow;
};

struct simd_state {
    unsigned int hashbitlen;
    unsigned int blocksize;
    unsigned int n_feistels;
    unsigned long long count;
    uint32_t *A, *B, *C, *D;
    unsigned char* buffer;
};

struct sm3_state{
    unsigned total[2];
    unsigned state[8];
    unsigned char buf[64];
};

struct snefru_state{
    unsigned s[16], cnt[2];
    unsigned char len;
    unsigned char buf[32];
};

union streebog512{unsigned long long QWORD[8];} __attribute__((__aligned__(16)));
struct streebog_state{
    unsigned char buffer[64]	__attribute__((__aligned__(16)));
    union streebog512 hash	__attribute__((__aligned__(16)));
    union streebog512 h		__attribute__((__aligned__(16)));
    union streebog512 N		__attribute__((__aligned__(16)));
    union streebog512 Sigma	__attribute__((__aligned__(16)));
    unsigned long bufsize;
    unsigned int digest_size;
};

struct swifftx_state{
    unsigned int remainingSize;
    unsigned short hashbitlen;
    unsigned char remaining[175 + 1];
    unsigned char currOutputBlock[65];
    unsigned char numOfBitsChar[8];
    unsigned char salt[8];
    bool wasUpdated;
};

struct tiger_state{
    unsigned long long s[3], len;
    unsigned long clen;
    unsigned char buf[64];
};

struct whirlpool_state{
    unsigned long long s[8], len;
    unsigned char buf[64];
    unsigned clen;
};

struct xxhash_state{
    unsigned long long s;
};




#pragma mark - HASH STATES
typedef union hash_state{
    char dummy[1];

    struct adler32_state 	adler32;
    struct blake2b_state	blake2b;
    struct blake2s_state	blake2s;
    struct chi_state		chi;
    struct crc8_state		crc8;
    struct crc16_state		crc16;
    struct crc24_state		crc24;
    struct crc32_state		crc32;
    struct crc64_state		crc64;
    struct echo_state		echo;
    struct fnv132_state		fnv132;
    struct fnv164_state		fnv164;
    struct gost_state		gost;
    struct groestl_state	groestl;
    struct hamsi_state		hamsi;
    struct haval_state		haval;
    struct jh_state		jh;
    struct joaat_state		joaat;
    struct lane_state		lane;
    struct lesamnta256_state	lesamnta256;
    struct lesamnta512_state	lesamnta512;
    struct luffa_state		luffa;
    struct md2_state		md2;
    struct md4_state		md4;
    struct md5_state		md5;
    struct murmur3a_state	murmur3a;
    struct murmur3c_state	murmur3c;
    struct murmur3f_state	murmur3f;
    struct ripemd128_state	ripemd128;
    struct ripemd160_state	ripemd160;
    struct ripemd256_state	ripemd256;
    struct ripemd320_state	ripemd320;
    struct sha1_state		sha1;
    struct sha256_state 	sha256;
    struct sha512_state		sha512;
    struct sha3_state		sha3;
    struct shabal_state		shabal;
    struct simd_state		simd;
    struct sm3_state		sm3;
    struct snefru_state		snefru;
    struct streebog_state	streebog;
    struct swifftx_state	swifftx;
    struct tiger_state 		tiger;
    struct whirlpool_state 	whirlpool;
    struct xxhash_state 	xxh;

    void *data;
} hash_state;




#pragma mark - HASH DESCRIPTOR
extern struct hash_descriptor {
    const char *name;
    unsigned char ID;
    unsigned long hashsize, blocksize;

    int (*init)(hash_state *hs);
    int (*process)(hash_state *hs, const unsigned char *in, unsigned long inlen);
    int (*done)(hash_state *hs, unsigned char *out);
    int (*hmac_block)(const unsigned char *key, unsigned long keylen, const unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);
} hash_descriptor[];




#pragma mark - HASH FUNCTIONS -

#pragma mark ADLER32
int adler32_init(hash_state *hs);
int adler32_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int adler32_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor adler32_desc;


#pragma mark BLAKE2B
int blake2b_160_init(hash_state *hs);
int blake2b_256_init(hash_state *hs);
int blake2b_384_init(hash_state *hs);
int blake2b_512_init(hash_state *hs);
int blake2b_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int blake2b_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor blake2b_160_desc;
extern const struct hash_descriptor blake2b_256_desc;
extern const struct hash_descriptor blake2b_384_desc;
extern const struct hash_descriptor blake2b_512_desc;


#pragma mark BLAKE2S
int blake2s_128_init(hash_state *hs);
int blake2s_160_init(hash_state *hs);
int blake2s_224_init(hash_state *hs);
int blake2s_256_init(hash_state *hs);
int blake2s_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int blake2s_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor blake2s_128_desc;
extern const struct hash_descriptor blake2s_160_desc;
extern const struct hash_descriptor blake2s_224_desc;
extern const struct hash_descriptor blake2s_256_desc;


#pragma mark CHI
int chi_224_init(hash_state *hs);
int chi_256_init(hash_state *hs);
int chi_384_init(hash_state *hs);
int chi_512_init(hash_state *hs);
int chi_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int chi_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor chi_224_desc;
extern const struct hash_descriptor chi_256_desc;
extern const struct hash_descriptor chi_384_desc;
extern const struct hash_descriptor chi_512_desc;


#pragma mark CRC8
int crc8_AUTOSAR_init(hash_state *hs);
int crc8_BLUETOOTH_init(hash_state *hs);
int crc8_CDMA2000_init(hash_state *hs);
int crc8_DARC_init(hash_state *hs);
int crc8_DVB_S2_init(hash_state *hs);
int crc8_GSM_A_init(hash_state *hs);
int crc8_GSM_B_init(hash_state *hs);
int crc8_HITAG_init(hash_state *hs);
int crc8_ICODE_init(hash_state *hs);
int crc8_ITU_init(hash_state *hs);
int crc8_LTE_init(hash_state *hs);
int crc8_MAXIM_init(hash_state *hs);
int crc8_MIFARE_MAD_init(hash_state *hs);
int crc8_NRSC_5_init(hash_state *hs);
int crc8_OPENSAFETY_init(hash_state *hs);
int crc8_ROHC_init(hash_state *hs);
int crc8_SAE_J1850_init(hash_state *hs);
int crc8_SMBUS_init(hash_state *hs);
int crc8_TECH_3250_init(hash_state *hs);
int crc8_WCDMA_init(hash_state *hs);
int crc8_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int crc8_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor crc8_AUTOSAR_desc;
extern const struct hash_descriptor crc8_BLUETOOTH_desc;
extern const struct hash_descriptor crc8_CDMA2000_desc;
extern const struct hash_descriptor crc8_DARC_desc;
extern const struct hash_descriptor crc8_DVB_S2_desc;
extern const struct hash_descriptor crc8_GSM_A_desc;
extern const struct hash_descriptor crc8_GSM_B_desc;
extern const struct hash_descriptor crc8_HITAG_desc;
extern const struct hash_descriptor crc8_ICODE_desc;
extern const struct hash_descriptor crc8_ITU_desc;
extern const struct hash_descriptor crc8_LTE_desc;
extern const struct hash_descriptor crc8_MAXIM_desc;
extern const struct hash_descriptor crc8_MIFARE_MAD_desc;
extern const struct hash_descriptor crc8_NRSC_5_desc;
extern const struct hash_descriptor crc8_OPENSAFETY_desc;
extern const struct hash_descriptor crc8_ROHC_desc;
extern const struct hash_descriptor crc8_SAE_J1850_desc;
extern const struct hash_descriptor crc8_SMBUS_desc;
extern const struct hash_descriptor crc8_TECH_3250_desc;
extern const struct hash_descriptor crc8_WCDMA_desc;


#pragma mark CRC16
int crc16_init(hash_state *hs);
int crc16_CDMA2000_init(hash_state *hs);
int crc16_CMS_init(hash_state *hs);
int crc16_DDS110_init(hash_state *hs);
int crc16_DECTR_init(hash_state *hs);
int crc16_DECTX_init(hash_state *hs);
int crc16_DNP_init(hash_state *hs);
int crc16_EN13757_init(hash_state *hs);
int crc16_GENIBUS_init(hash_state *hs);
int crc16_GSM_init(hash_state *hs);
int crc16_IBM3740_init(hash_state *hs);
int crc16_IBMSDLC_init(hash_state *hs);
int crc16_ISO_IEC_14443_3_A_init(hash_state *hs);
int crc16_KERMIT_init(hash_state *hs);
int crc16_LJ1200_init(hash_state *hs);
int crc16_M17_init(hash_state *hs);
int crc16_MAXIM_init(hash_state *hs);
int crc16_MCRF4XX_init(hash_state *hs);
int crc16_MODBUS_init(hash_state *hs);
int crc16_NRSC5_init(hash_state *hs);
int crc16_OPENSAFETY_A_init(hash_state *hs);
int crc16_OPENSAFETY_B_init(hash_state *hs);
int crc16_PROFIBUS_init(hash_state *hs);
int crc16_RIELLO_init(hash_state *hs);
int crc16_SPI_FUJITSU_init(hash_state *hs);
int crc16_TELEDISK_init(hash_state *hs);
int crc16_T10DIF_init(hash_state *hs);
int crc16_TMS37157_init(hash_state *hs);
int crc16_UMTS_init(hash_state *hs);
int crc16_USB_init(hash_state *hs);
int crc16_XMODEM_init(hash_state *hs);
int crc16_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int crc16_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor crc16_desc;
extern const struct hash_descriptor crc16_CDMA2000_desc;
extern const struct hash_descriptor crc16_CMS_desc;
extern const struct hash_descriptor crc16_DDS110_desc;
extern const struct hash_descriptor crc16_DECTR_desc;
extern const struct hash_descriptor crc16_DECTX_desc;
extern const struct hash_descriptor crc16_DNP_desc;
extern const struct hash_descriptor crc16_EN13757_desc;
extern const struct hash_descriptor crc16_GENIBUS_desc;
extern const struct hash_descriptor crc16_GSM_desc;
extern const struct hash_descriptor crc16_IBM3740_desc;
extern const struct hash_descriptor crc16_IBMSDLC_desc;
extern const struct hash_descriptor crc16_ISO_IEC_14443_3_A_desc;
extern const struct hash_descriptor crc16_KERMIT_desc;
extern const struct hash_descriptor crc16_LJ1200_desc;
extern const struct hash_descriptor crc16_M17_desc;
extern const struct hash_descriptor crc16_MAXIM_desc;
extern const struct hash_descriptor crc16_MCRF4XX_desc;
extern const struct hash_descriptor crc16_MODBUS_desc;
extern const struct hash_descriptor crc16_NRSC5_desc;
extern const struct hash_descriptor crc16_OPENSAFETY_A_desc;
extern const struct hash_descriptor crc16_OPENSAFETY_B_desc;
extern const struct hash_descriptor crc16_PROFIBUS_desc;
extern const struct hash_descriptor crc16_RIELLO_desc;
extern const struct hash_descriptor crc16_SPI_FUJITSU_desc;
extern const struct hash_descriptor crc16_TELEDISK_desc;
extern const struct hash_descriptor crc16_T10DIF_desc;
extern const struct hash_descriptor crc16_TMS37157_desc;
extern const struct hash_descriptor crc16_UMTS_desc;
extern const struct hash_descriptor crc16_USB_desc;
extern const struct hash_descriptor crc16_XMODEM_desc;


#pragma mark CRC24
int crc24_BLE_init(hash_state *hs);
int crc24_FLEXRAY_A_init(hash_state *hs);
int crc24_FLEXRAY_B_init(hash_state *hs);
int crc24_INTERLAKEN_init(hash_state *hs);
int crc24_LTE_A_init(hash_state *hs);
int crc24_LTE_B_init(hash_state *hs);
int crc24_OPENPGP_init(hash_state *hs);
int crc24_OS_9_init(hash_state *hs);
int crc24_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int crc24_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor crc24_BLE_desc;
extern const struct hash_descriptor crc24_FLEXRAY_A_desc;
extern const struct hash_descriptor crc24_FLEXRAY_B_desc;
extern const struct hash_descriptor crc24_INTERLAKEN_desc;
extern const struct hash_descriptor crc24_LTE_A_desc;
extern const struct hash_descriptor crc24_LTE_B_desc;
extern const struct hash_descriptor crc24_OPENPGP_desc;
extern const struct hash_descriptor crc24_OS_9_desc;


#pragma mark CRC32
int crc32_AIXM_init(hash_state *hs);
int crc32_AUTOSAR_init(hash_state *hs);
int crc32_BASE91_D_init(hash_state *hs);
int crc32_BZIP2_init(hash_state *hs);
int crc32_CD_ROM_EDC_init(hash_state *hs);
int crc32_CKSUM_init(hash_state *hs);
int crc32_ISCSI_init(hash_state *hs);
int crc32_ISO_HDLC_init(hash_state *hs);
int crc32_JAMCRC_init(hash_state *hs);
int crc32_MEF_init(hash_state *hs);
int crc32_MPEG2_init(hash_state *hs);
int crc32_XFER_init(hash_state *hs);
int crc32_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int crc32_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor crc32_AIXM_desc;
extern const struct hash_descriptor crc32_AUTOSAR_desc;
extern const struct hash_descriptor crc32_BASE91_D_desc;
extern const struct hash_descriptor crc32_BZIP2_desc;
extern const struct hash_descriptor crc32_CD_ROM_EDC_desc;
extern const struct hash_descriptor crc32_CKSUM_desc;
extern const struct hash_descriptor crc32_ISCSI_desc;
extern const struct hash_descriptor crc32_ISO_HDLC_desc;
extern const struct hash_descriptor crc32_JAMCRC_desc;
extern const struct hash_descriptor crc32_MEF_desc;
extern const struct hash_descriptor crc32_MPEG2_desc;
extern const struct hash_descriptor crc32_XFER_desc;


#pragma mark CRC64
int crc64_ECMA_182_init(hash_state *hs);
int crc64_ISO_3309_init(hash_state *hs);
int crc64_MS_init(hash_state *hs);
int crc64_NVME_init(hash_state *hs);
int crc64_REDIS_init(hash_state *hs);
int crc64_WE_init(hash_state *hs);
int crc64_XZ_init(hash_state *hs);
int crc64_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int crc64_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor crc64_ECMA_182_desc;
extern const struct hash_descriptor crc64_ISO_3309_desc;
extern const struct hash_descriptor crc64_MS_desc;
extern const struct hash_descriptor crc64_NVME_desc;
extern const struct hash_descriptor crc64_REDIS_desc;
extern const struct hash_descriptor crc64_WE_desc;
extern const struct hash_descriptor crc64_XZ_desc;


#pragma mark ECHO
int echo_224_init(hash_state *hs);
int echo_256_init(hash_state *hs);
int echo_384_init(hash_state *hs);
int echo_512_init(hash_state *hs);
int echo_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int echo_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor echo_224_desc;
extern const struct hash_descriptor echo_256_desc;
extern const struct hash_descriptor echo_384_desc;
extern const struct hash_descriptor echo_512_desc;


#pragma mark FNV
int fnv1_32_init(hash_state *hs);
int fnv1_32_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int fnv1a_32_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int fnv1_32_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor fnv1_32_desc;
extern const struct hash_descriptor fnv1a_32_desc;

int fnv1_64_init(hash_state *hs);
int fnv1_64_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int fnv1a_64_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int fnv1_64_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor fnv1_64_desc;
extern const struct hash_descriptor fnv1a_64_desc;


#pragma mark GOST
int gost_init(hash_state *hs);
int gost_crypto_init(hash_state *hs);
int gost_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int gost_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor gost_desc;
extern const struct hash_descriptor gost_crypto_desc;


#pragma mark GROESTL
int groestl_224_init(hash_state *hs);
int groestl_256_init(hash_state *hs);
int groestl_384_init(hash_state *hs);
int groestl_512_init(hash_state *hs);
int groestl_process(hash_state* hs, const unsigned char *in, unsigned long inlen);
int groestl_done(hash_state* hs, unsigned char *out);
extern const struct hash_descriptor groestl_224_desc;
extern const struct hash_descriptor groestl_256_desc;
extern const struct hash_descriptor groestl_384_desc;
extern const struct hash_descriptor groestl_512_desc;


#pragma mark HAMSI
int hamsi_224_init(hash_state *hs);
int hamsi_256_init(hash_state *hs);
int hamsi_384_init(hash_state *hs);
int hamsi_512_init(hash_state *hs);
int hamsi_process(hash_state* hs, const unsigned char *in, unsigned long inlen);
int hamsi_done(hash_state* hs, unsigned char *out);
extern const struct hash_descriptor hamsi_224_desc;
extern const struct hash_descriptor hamsi_256_desc;
extern const struct hash_descriptor hamsi_384_desc;
extern const struct hash_descriptor hamsi_512_desc;


#pragma mark HAVAL
int haval_128_3_init(hash_state *hs);
int haval_160_3_init(hash_state *hs);
int haval_192_3_init(hash_state *hs);
int haval_224_3_init(hash_state *hs);
int haval_256_3_init(hash_state *hs);
int haval_128_4_init(hash_state *hs);
int haval_160_4_init(hash_state *hs);
int haval_192_4_init(hash_state *hs);
int haval_224_4_init(hash_state *hs);
int haval_256_4_init(hash_state *hs);
int haval_128_5_init(hash_state *hs);
int haval_160_5_init(hash_state *hs);
int haval_192_5_init(hash_state *hs);
int haval_224_5_init(hash_state *hs);
int haval_256_5_init(hash_state *hs);
int haval_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int haval_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor haval_128_3_desc;
extern const struct hash_descriptor haval_160_3_desc;
extern const struct hash_descriptor haval_192_3_desc;
extern const struct hash_descriptor haval_224_3_desc;
extern const struct hash_descriptor haval_256_3_desc;
extern const struct hash_descriptor haval_128_4_desc;
extern const struct hash_descriptor haval_160_4_desc;
extern const struct hash_descriptor haval_192_4_desc;
extern const struct hash_descriptor haval_224_4_desc;
extern const struct hash_descriptor haval_256_4_desc;
extern const struct hash_descriptor haval_128_5_desc;
extern const struct hash_descriptor haval_160_5_desc;
extern const struct hash_descriptor haval_192_5_desc;
extern const struct hash_descriptor haval_224_5_desc;
extern const struct hash_descriptor haval_256_5_desc;


#pragma mark JH
int jh_224_init(hash_state *hs);
int jh_256_init(hash_state *hs);
int jh_384_init(hash_state *hs);
int jh_512_init(hash_state *hs);
int jh_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int jh_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor jh_224_desc;
extern const struct hash_descriptor jh_256_desc;
extern const struct hash_descriptor jh_384_desc;
extern const struct hash_descriptor jh_512_desc;


#pragma mark JOAAT
int joaat_init(hash_state *hs);
int joaat_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int joaat_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor joaat_desc;


#pragma mark LANE
int lane_224_init(hash_state *hs);
int lane_256_init(hash_state *hs);
int lane_384_init(hash_state *hs);
int lane_512_init(hash_state *hs);
int lane_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int lane_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor lane_224_desc;
extern const struct hash_descriptor lane_256_desc;
extern const struct hash_descriptor lane_384_desc;
extern const struct hash_descriptor lane_512_desc;


#pragma mark LESAMNTA
int lesamnta_224_init(hash_state *hs);
int lesamnta_224_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int lesamnta_224_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor lesamnta_224_desc;

int lesamnta_256_init(hash_state *hs);
int lesamnta_256_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int lesamnta_256_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor lesamnta_256_desc;

int lesamnta_384_init(hash_state *hs);
int lesamnta_384_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int lesamnta_384_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor lesamnta_384_desc;

int lesamnta_512_init(hash_state *hs);
int lesamnta_512_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int lesamnta_512_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor lesamnta_512_desc;


#pragma mark LUFFA
int luffa_224_init(hash_state *hs);
int luffa_256_init(hash_state *hs);
int luffa_384_init(hash_state *hs);
int luffa_512_init(hash_state *hs);
int luffa_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int luffa_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor luffa_224_desc;
extern const struct hash_descriptor luffa_256_desc;
extern const struct hash_descriptor luffa_384_desc;
extern const struct hash_descriptor luffa_512_desc;


#pragma mark MD2
int md2_init(hash_state *hs);
int md2_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int md2_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor md2_desc;


#pragma mark MD4
int md4_init(hash_state *hs);
int md4_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int md4_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor md4_desc;


#pragma mark MD5
int md5_init(hash_state *hs);
int md5_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int md5_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor md5_desc;


#pragma mark MURMUR
int murmur3a_init(hash_state *hs);
int murmur3a_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int murmur3a_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor murmur3a_desc;

int murmur3c_init(hash_state *hs);
int murmur3c_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int murmur3c_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor murmur3c_desc;

int murmur3f_init(hash_state *hs);
int murmur3f_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int murmur3f_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor murmur3f_desc;


#pragma mark RIPEMD
int ripemd_128_init(hash_state *hs);
int ripemd_128_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int ripemd_128_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor ripemd_128_desc;

int ripemd_160_init(hash_state *hs);
int ripemd_160_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int ripemd_160_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor ripemd_160_desc;

int ripemd_256_init(hash_state *hs);
int ripemd_256_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int ripemd_256_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor ripemd_256_desc;

int ripemd_320_init(hash_state *hs);
int ripemd_320_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int ripemd_320_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor ripemd_320_desc;


#pragma mark SHA1
int sha1_init(hash_state *hs);
int sha1_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int sha1_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor sha1_desc;


#pragma mark SHA2
int sha224_init(hash_state *hs);
#define sha224_process sha256_process
int sha224_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor sha224_desc;

int sha256_init(hash_state *hs);
int sha256_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int sha256_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor sha256_desc;

int sha384_init(hash_state *hs);
#define sha384_process sha512_process
int sha384_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor sha384_desc;

int sha512_init(hash_state *hs);
int sha512_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int sha512_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor sha512_desc;

int sha512_224_init(hash_state *hs);
#define sha512_224_process sha512_process
int sha512_224_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor sha512_224_desc;

int sha512_256_init(hash_state *hs);
#define sha512_256_process sha512_process
int sha512_256_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor sha512_256_desc;


#pragma mark SHA3
int sha3_224_init(hash_state *hs);
int sha3_256_init(hash_state *hs);
int sha3_384_init(hash_state *hs);
int sha3_512_init(hash_state *hs);
int sha3_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int sha3_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor sha3_224_desc;
extern const struct hash_descriptor sha3_256_desc;
extern const struct hash_descriptor sha3_384_desc;
extern const struct hash_descriptor sha3_512_desc;

#define keccak_224_init(a)	sha3_224_init(a)
#define keccak_256_init(a)	sha3_256_init(a)
#define keccak_384_init(a)	sha3_384_init(a)
#define keccak_512_init(a)	sha3_512_init(a)
#define keccak_process(a,b,c)	sha3_process(a,b,c)
int keccak_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor keccak_224_desc;
extern const struct hash_descriptor keccak_256_desc;
extern const struct hash_descriptor keccak_384_desc;
extern const struct hash_descriptor keccak_512_desc;

int sha3_shake_128_init(hash_state *hs);
int sha3_shake_256_init(hash_state *hs);
#define sha3_shake_process(a,b,c) sha3_process(a,b,c)
int sha3_shake_done(hash_state *hs, unsigned char *out, unsigned long outlen);
extern const struct hash_descriptor shake_128_desc;
extern const struct hash_descriptor shake_256_desc;


#pragma mark SHABAL
int shabal_192_init(hash_state *hs);
int shabal_224_init(hash_state *hs);
int shabal_256_init(hash_state *hs);
int shabal_384_init(hash_state *hs);
int shabal_512_init(hash_state *hs);
int shabal_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int shabal_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor shabal_192_desc;
extern const struct hash_descriptor shabal_224_desc;
extern const struct hash_descriptor shabal_256_desc;
extern const struct hash_descriptor shabal_384_desc;
extern const struct hash_descriptor shabal_512_desc;


#pragma mark SIMD
int simd_224_init(hash_state *hs);
int simd_256_init(hash_state *hs);
int simd_384_init(hash_state *hs);
int simd_512_init(hash_state *hs);
int simd_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int simd_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor simd_224_desc;
extern const struct hash_descriptor simd_256_desc;
extern const struct hash_descriptor simd_384_desc;
extern const struct hash_descriptor simd_512_desc;


#pragma mark SM3
int sm3_init(hash_state *hs);
int sm3_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int sm3_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor sm3_desc;


#pragma mark SNEFRU
int snefru_init(hash_state *hs);
int snefru_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int snefru_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor snefru_desc;


#pragma mark STREEBOG
int streebog_256_init(hash_state *hs);
int streebog_512_init(hash_state *hs);
int streebog_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int streebog_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor streebog_256_desc;
extern const struct hash_descriptor streebog_512_desc;


#pragma mark SWIFFTX
int swifftx_224_init(hash_state *hs);
int swifftx_256_init(hash_state *hs);
int swifftx_384_init(hash_state *hs);
int swifftx_512_init(hash_state *hs);
int swifftx_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int swifftx_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor swifftx_224_desc;
extern const struct hash_descriptor swifftx_256_desc;
extern const struct hash_descriptor swifftx_384_desc;
extern const struct hash_descriptor swifftx_512_desc;


#pragma mark TIGER
int tiger_init(hash_state *hs);
int tiger_3_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int tiger_4_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int tiger1_3_done(hash_state *hs, unsigned char *out);
int tiger1_4_done(hash_state *hs, unsigned char *out);
int tiger2_3_done(hash_state *hs, unsigned char *out);
int tiger2_4_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor tiger1_128_3_desc;
extern const struct hash_descriptor tiger1_160_3_desc;
extern const struct hash_descriptor tiger1_192_3_desc;
extern const struct hash_descriptor tiger1_128_4_desc;
extern const struct hash_descriptor tiger1_160_4_desc;
extern const struct hash_descriptor tiger1_192_4_desc;
extern const struct hash_descriptor tiger2_128_3_desc;
extern const struct hash_descriptor tiger2_160_3_desc;
extern const struct hash_descriptor tiger2_192_3_desc;
extern const struct hash_descriptor tiger2_128_4_desc;
extern const struct hash_descriptor tiger2_160_4_desc;
extern const struct hash_descriptor tiger2_192_4_desc;


#pragma mark WHIRLPOOL
int whirlpool_init(hash_state *hs);
int whirlpool_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int whirlpool_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor whirlpool_desc;


#pragma mark XXHASH
#define XXH_INLINE_ALL 1

int xxh3_64_init(hash_state *hs);
int xxh3_64_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int xxh3_64_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor xxh3_64_desc;

int xxh3_128_init(hash_state *hs);
int xxh3_128_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int xxh3_128_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor xxh3_128_desc;

int xxh_32_init(hash_state *hs);
int xxh_32_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int xxh_32_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor xxh_32_desc;

int xxh_64_init(hash_state *hs);
int xxh_64_process(hash_state *hs, const unsigned char *in, unsigned long inlen);
int xxh_64_done(hash_state *hs, unsigned char *out);
extern const struct hash_descriptor xxh_64_desc;




#pragma mark - HASH GLOBAL FUNCTIONS
int is_hash_valid(int idx);
int register_hash(const struct hash_descriptor *hash);
int unregister_hash(const struct hash_descriptor *hash);


#endif /* nbs_hashes_h */
