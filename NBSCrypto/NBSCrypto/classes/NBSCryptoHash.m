//
//	NBSCryptoHash.m
//	NBSCrypto
//

#import "NBSCryptoHash.h"
#import "NBSCryptoDefines_Internal.h"
#import "nbs_crypto.h"

@implementation NBSCryptoHash


@synthesize ALGORITHM	= _algorithm;
@synthesize KEY		= _key;
@synthesize MAC		= _mac;


- (const struct hash_descriptor*)_getHashDescriptor
{
    const struct hash_descriptor* r = NULL;

    switch (_algorithm) {
	case NBSCrypto_HASH_ADLER32:			{r=&adler32_desc;break;}
	case NBSCrypto_HASH_BLAKE2B_160:		{r=&blake2b_160_desc;break;}
	case NBSCrypto_HASH_BLAKE2B_256:		{r=&blake2b_256_desc;break;}
	case NBSCrypto_HASH_BLAKE2B_384:		{r=&blake2b_384_desc;break;}
	case NBSCrypto_HASH_BLAKE2B_512:		{r=&blake2b_512_desc;break;}
	case NBSCrypto_HASH_BLAKE2S_128:		{r=&blake2s_128_desc;break;}
	case NBSCrypto_HASH_BLAKE2S_160:		{r=&blake2s_160_desc;break;}
	case NBSCrypto_HASH_BLAKE2S_224:		{r=&blake2s_224_desc;break;}
	case NBSCrypto_HASH_BLAKE2S_256:		{r=&blake2s_256_desc;break;}
	case NBSCrypto_HASH_CRC8_AUTOSAR:		{r=&crc8_AUTOSAR_desc;break;}
	case NBSCrypto_HASH_CRC8_BLUETOOTH:		{r=&crc8_BLUETOOTH_desc;break;}
	case NBSCrypto_HASH_CRC8_CDMA2000:		{r=&crc8_CDMA2000_desc;break;}
	case NBSCrypto_HASH_CRC8_DARC:			{r=&crc8_DARC_desc;break;}
	case NBSCrypto_HASH_CRC8_DVB_S2:		{r=&crc8_DVB_S2_desc;break;}
	case NBSCrypto_HASH_CRC8_GSM_A:			{r=&crc8_GSM_A_desc;break;}
	case NBSCrypto_HASH_CRC8_GSM_B:			{r=&crc8_GSM_B_desc;break;}
	case NBSCrypto_HASH_CRC8_HITAG:			{r=&crc8_HITAG_desc;break;}
	case NBSCrypto_HASH_CRC8_ICODE:			{r=&crc8_ICODE_desc;break;}
	case NBSCrypto_HASH_CRC8_ITU:			{r=&crc8_ITU_desc;break;}
	case NBSCrypto_HASH_CRC8_LTE:			{r=&crc8_LTE_desc;break;}
	case NBSCrypto_HASH_CRC8_MAXIM:			{r=&crc8_MAXIM_desc;break;}
	case NBSCrypto_HASH_CRC8_MIFARE_MAD:		{r=&crc8_MIFARE_MAD_desc;break;}
	case NBSCrypto_HASH_CRC8_NRSC_5:		{r=&crc8_NRSC_5_desc;break;}
	case NBSCrypto_HASH_CRC8_OPENSAFETY:		{r=&crc8_OPENSAFETY_desc;break;}
	case NBSCrypto_HASH_CRC8_ROHC:			{r=&crc8_ROHC_desc;break;}
	case NBSCrypto_HASH_CRC8_SAE_J1850:		{r=&crc8_SAE_J1850_desc;break;}
	case NBSCrypto_HASH_CRC8_SMBUS:			{r=&crc8_SMBUS_desc;break;}
	case NBSCrypto_HASH_CRC8_TECH_3250:		{r=&crc8_TECH_3250_desc;break;}
	case NBSCrypto_HASH_CRC8_WCDMA:			{r=&crc8_WCDMA_desc;break;}
	case NBSCrypto_HASH_CRC16:			{r=&crc16_desc;break;}
	case NBSCrypto_HASH_CRC16_CDMA2000:		{r=&crc16_CDMA2000_desc;break;}
	case NBSCrypto_HASH_CRC16_CMS:			{r=&crc16_CMS_desc;break;}
	case NBSCrypto_HASH_CRC16_DDS110:		{r=&crc16_DDS110_desc;break;}
	case NBSCrypto_HASH_CRC16_DECT_R:		{r=&crc16_DECTR_desc;break;}
	case NBSCrypto_HASH_CRC16_DECT_X:		{r=&crc16_DECTX_desc;break;}
	case NBSCrypto_HASH_CRC16_DNP:			{r=&crc16_DNP_desc;break;}
	case NBSCrypto_HASH_CRC16_EN_13757:		{r=&crc16_EN13757_desc;break;}
	case NBSCrypto_HASH_CRC16_GENIBUS:		{r=&crc16_GENIBUS_desc;break;}
	case NBSCrypto_HASH_CRC16_GSM:			{r=&crc16_GSM_desc;break;}
	case NBSCrypto_HASH_CRC16_IBM_3740:		{r=&crc16_IBM3740_desc;break;}
	case NBSCrypto_HASH_CRC16_IBM_SDLC:		{r=&crc16_IBMSDLC_desc;break;}
	case NBSCrypto_HASH_CRC16_ISO_IEC_14443_3_A:	{r=&crc16_ISO_IEC_14443_3_A_desc;break;}
	case NBSCrypto_HASH_CRC16_KERMIT:		{r=&crc16_KERMIT_desc;break;}
	case NBSCrypto_HASH_CRC16_LJ1200:		{r=&crc16_LJ1200_desc;break;}
	case NBSCrypto_HASH_CRC16_M17:			{r=&crc16_M17_desc;break;}
	case NBSCrypto_HASH_CRC16_MAXIM:		{r=&crc16_MAXIM_desc;break;}
	case NBSCrypto_HASH_CRC16_MCRF4XX:		{r=&crc16_MCRF4XX_desc;break;}
	case NBSCrypto_HASH_CRC16_MODBUS:		{r=&crc16_MODBUS_desc;break;}
	case NBSCrypto_HASH_CRC16_NRSC_5:		{r=&crc16_NRSC5_desc;break;}
	case NBSCrypto_HASH_CRC16_OPENSAFETY_A:		{r=&crc16_OPENSAFETY_A_desc;break;}
	case NBSCrypto_HASH_CRC16_OPENSAFETY_B:		{r=&crc16_OPENSAFETY_B_desc;break;}
	case NBSCrypto_HASH_CRC16_PROFIBUS:		{r=&crc16_PROFIBUS_desc;break;}
	case NBSCrypto_HASH_CRC16_RIELLO:		{r=&crc16_RIELLO_desc;break;}
	case NBSCrypto_HASH_CRC16_SPI_FUJITSU:		{r=&crc16_SPI_FUJITSU_desc;break;}
	case NBSCrypto_HASH_CRC16_T10_DIF:		{r=&crc16_T10DIF_desc;break;}
	case NBSCrypto_HASH_CRC16_TELEDISK:		{r=&crc16_TELEDISK_desc;break;}
	case NBSCrypto_HASH_CRC16_TMS37157:		{r=&crc16_TMS37157_desc;break;}
	case NBSCrypto_HASH_CRC16_UMTS:			{r=&crc16_UMTS_desc;break;}
	case NBSCrypto_HASH_CRC16_USB:			{r=&crc16_USB_desc;break;}
	case NBSCrypto_HASH_CRC16_XMODEM:		{r=&crc16_XMODEM_desc;break;}
	case NBSCrypto_HASH_CRC24_BLE:			{r=&crc24_BLE_desc;break;}
	case NBSCrypto_HASH_CRC24_FLEXRAY_A:		{r=&crc24_FLEXRAY_A_desc;break;}
	case NBSCrypto_HASH_CRC24_FLEXRAY_B:		{r=&crc24_FLEXRAY_B_desc;break;}
	case NBSCrypto_HASH_CRC24_INTERLAKEN:		{r=&crc24_INTERLAKEN_desc;break;}
	case NBSCrypto_HASH_CRC24_LTE_A:		{r=&crc24_LTE_A_desc;break;}
	case NBSCrypto_HASH_CRC24_LTE_B:		{r=&crc24_LTE_B_desc;break;}
	case NBSCrypto_HASH_CRC24_OPENPGP:		{r=&crc24_OPENPGP_desc;break;}
	case NBSCrypto_HASH_CRC24_OS_9:			{r=&crc24_OS_9_desc;break;}
	case NBSCrypto_HASH_CRC32_AIXM:			{r=&crc32_AIXM_desc;break;}
	case NBSCrypto_HASH_CRC32_AUTOSAR:		{r=&crc32_AUTOSAR_desc;break;}
	case NBSCrypto_HASH_CRC32_BASE91_D:		{r=&crc32_BASE91_D_desc;break;}
	case NBSCrypto_HASH_CRC32_BZIP2:		{r=&crc32_BZIP2_desc;break;}
	case NBSCrypto_HASH_CRC32_CD_ROM_EDC:		{r=&crc32_CD_ROM_EDC_desc;break;}
	case NBSCrypto_HASH_CRC32_CKSUM:		{r=&crc32_CKSUM_desc;break;}
	case NBSCrypto_HASH_CRC32_ISCSI:		{r=&crc32_ISCSI_desc;break;}
	case NBSCrypto_HASH_CRC32_ISO_HDLC:		{r=&crc32_ISO_HDLC_desc;break;}
	case NBSCrypto_HASH_CRC32_JAMCRC:		{r=&crc32_JAMCRC_desc;break;}
	case NBSCrypto_HASH_CRC32_MEF:			{r=&crc32_MEF_desc;break;}
	case NBSCrypto_HASH_CRC32_MPEG2:		{r=&crc32_MPEG2_desc;break;}
	case NBSCrypto_HASH_CRC32_XFER:			{r=&crc32_XFER_desc;break;}
	case NBSCrypto_HASH_CRC64_ECMA_182:		{r=&crc64_ECMA_182_desc;break;}
	case NBSCrypto_HASH_CRC64_ISO_3309:		{r=&crc64_ISO_3309_desc;break;}
	case NBSCrypto_HASH_CRC64_MS:			{r=&crc64_MS_desc;break;}
	case NBSCrypto_HASH_CRC64_NVME:			{r=&crc64_NVME_desc;break;}
	case NBSCrypto_HASH_CRC64_REDIS:		{r=&crc64_REDIS_desc;break;}
	case NBSCrypto_HASH_CRC64_WE:			{r=&crc64_WE_desc;break;}
	case NBSCrypto_HASH_CRC64_XZ:			{r=&crc64_XZ_desc;break;}
	case NBSCrypto_HASH_ECHO_224:			{r=&echo_224_desc;break;}
	case NBSCrypto_HASH_ECHO_256:			{r=&echo_256_desc;break;}
	case NBSCrypto_HASH_ECHO_384:			{r=&echo_384_desc;break;}
	case NBSCrypto_HASH_ECHO_512:			{r=&echo_512_desc;break;}
	case NBSCrypto_HASH_FNV132:			{r=&fnv1_32_desc;break;}
	case NBSCrypto_HASH_FNV1a32:			{r=&fnv1a_32_desc;break;}
	case NBSCrypto_HASH_FNV164:			{r=&fnv1_64_desc;break;}
	case NBSCrypto_HASH_FNV1a64:			{r=&fnv1a_64_desc;break;}
	case NBSCrypto_HASH_GOST:			{r=&gost_desc;break;}
	case NBSCrypto_HASH_GOST_CRYPTO:		{r=&gost_crypto_desc;break;}
	case NBSCrypto_HASH_GROESTL_224:		{r=&groestl_224_desc;break;}
	case NBSCrypto_HASH_GROESTL_256:		{r=&groestl_256_desc;break;}
	case NBSCrypto_HASH_GROESTL_384:		{r=&groestl_384_desc;break;}
	case NBSCrypto_HASH_GROESTL_512:		{r=&groestl_512_desc;break;}
	case NBSCrypto_HASH_HAMSI_224:			{r=&hamsi_224_desc;break;}
	case NBSCrypto_HASH_HAMSI_256:			{r=&hamsi_256_desc;break;}
	case NBSCrypto_HASH_HAMSI_384:			{r=&hamsi_384_desc;break;}
	case NBSCrypto_HASH_HAMSI_512:			{r=&hamsi_512_desc;break;}
	case NBSCrypto_HASH_HAVAL_128_3:		{r=&haval_128_3_desc;break;}
	case NBSCrypto_HASH_HAVAL_160_3:		{r=&haval_160_3_desc;break;}
	case NBSCrypto_HASH_HAVAL_192_3:		{r=&haval_192_3_desc;break;}
	case NBSCrypto_HASH_HAVAL_224_3:		{r=&haval_224_3_desc;break;}
	case NBSCrypto_HASH_HAVAL_256_3:		{r=&haval_256_3_desc;break;}
	case NBSCrypto_HASH_HAVAL_128_4:		{r=&haval_128_4_desc;break;}
	case NBSCrypto_HASH_HAVAL_160_4:		{r=&haval_160_4_desc;break;}
	case NBSCrypto_HASH_HAVAL_192_4:		{r=&haval_192_4_desc;break;}
	case NBSCrypto_HASH_HAVAL_224_4:		{r=&haval_224_4_desc;break;}
	case NBSCrypto_HASH_HAVAL_256_4:		{r=&haval_256_4_desc;break;}
	case NBSCrypto_HASH_HAVAL_128_5:		{r=&haval_128_5_desc;break;}
	case NBSCrypto_HASH_HAVAL_160_5:		{r=&haval_160_5_desc;break;}
	case NBSCrypto_HASH_HAVAL_192_5:		{r=&haval_192_5_desc;break;}
	case NBSCrypto_HASH_HAVAL_224_5:		{r=&haval_224_5_desc;break;}
	case NBSCrypto_HASH_HAVAL_256_5:		{r=&haval_256_5_desc;break;}
	case NBSCrypto_HASH_JH_224:			{r=&jh_224_desc;break;}
	case NBSCrypto_HASH_JH_256:			{r=&jh_256_desc;break;}
	case NBSCrypto_HASH_JH_384:			{r=&jh_384_desc;break;}
	case NBSCrypto_HASH_JH_512:			{r=&jh_512_desc;break;}
	case NBSCrypto_HASH_JOAAT:			{r=&joaat_desc;break;}
	case NBSCrypto_HASH_KECCAK_224:			{r=&keccak_224_desc;break;}
	case NBSCrypto_HASH_KECCAK_256:			{r=&keccak_256_desc;break;}
	case NBSCrypto_HASH_KECCAK_384:			{r=&keccak_384_desc;break;}
	case NBSCrypto_HASH_KECCAK_512:			{r=&keccak_512_desc;break;}
	case NBSCrypto_HASH_LANE_224:			{r=&lane_224_desc;break;}
	case NBSCrypto_HASH_LANE_256:			{r=&lane_256_desc;break;}
	case NBSCrypto_HASH_LANE_384:			{r=&lane_384_desc;break;}
	case NBSCrypto_HASH_LANE_512:			{r=&lane_512_desc;break;}
	case NBSCrypto_HASH_LESAMNTA_224:		{r=&lesamnta_224_desc;break;}
	case NBSCrypto_HASH_LESAMNTA_256:		{r=&lesamnta_256_desc;break;}
	case NBSCrypto_HASH_LESAMNTA_384:		{r=&lesamnta_384_desc;break;}
	case NBSCrypto_HASH_LESAMNTA_512:		{r=&lesamnta_512_desc;break;}
	case NBSCrypto_HASH_LUFFA_224:			{r=&luffa_224_desc;break;}
	case NBSCrypto_HASH_LUFFA_256:			{r=&luffa_256_desc;break;}
	case NBSCrypto_HASH_LUFFA_384:			{r=&luffa_384_desc;break;}
	case NBSCrypto_HASH_LUFFA_512:			{r=&luffa_512_desc;break;}
	case NBSCrypto_HASH_MD2:			{r=&md2_desc;break;}
	case NBSCrypto_HASH_MD4:			{r=&md4_desc;break;}
	case NBSCrypto_HASH_MD5:			{r=&md5_desc;break;}
	case NBSCrypto_HASH_MURMUR3A:			{r=&murmur3a_desc;break;}
	case NBSCrypto_HASH_MURMUR3C:			{r=&murmur3c_desc;break;}
	case NBSCrypto_HASH_MURMUR3F:			{r=&murmur3f_desc;break;}
	case NBSCrypto_HASH_RIPEMD_128:			{r=&ripemd_128_desc;break;}
	case NBSCrypto_HASH_RIPEMD_160:			{r=&ripemd_160_desc;break;}
	case NBSCrypto_HASH_RIPEMD_256:			{r=&ripemd_256_desc;break;}
	case NBSCrypto_HASH_RIPEMD_320:			{r=&ripemd_320_desc;break;}
	case NBSCrypto_HASH_SHA1:			{r=&sha1_desc;break;}
	case NBSCrypto_HASH_SHA224:			{r=&sha224_desc;break;}
	case NBSCrypto_HASH_SHA256:			{r=&sha256_desc;break;}
	case NBSCrypto_HASH_SHA384:			{r=&sha384_desc;break;}
	case NBSCrypto_HASH_SHA512:			{r=&sha512_desc;break;}
	case NBSCrypto_HASH_SHA512_224:			{r=&sha512_224_desc;break;}
	case NBSCrypto_HASH_SHA512_256:			{r=&sha512_256_desc;break;}
	case NBSCrypto_HASH_SHA3_224:			{r=&sha3_224_desc;break;}
	case NBSCrypto_HASH_SHA3_256:			{r=&sha3_256_desc;break;}
	case NBSCrypto_HASH_SHA3_384:			{r=&sha3_384_desc;break;}
	case NBSCrypto_HASH_SHA3_512:			{r=&sha3_512_desc;break;}
	case NBSCrypto_HASH_SHABAL_192:			{r=&shabal_192_desc;break;}
	case NBSCrypto_HASH_SHABAL_224:			{r=&shabal_224_desc;break;}
	case NBSCrypto_HASH_SHABAL_256:			{r=&shabal_256_desc;break;}
	case NBSCrypto_HASH_SHABAL_384:			{r=&shabal_384_desc;break;}
	case NBSCrypto_HASH_SHABAL_512:			{r=&shabal_512_desc;break;}
	case NBSCrypto_HASH_SHAKE_128:			{r=&shake_128_desc;break;}
	case NBSCrypto_HASH_SHAKE_256:			{r=&shake_256_desc;break;}
	case NBSCrypto_HASH_SIMD_224:			{r=&simd_224_desc;break;}
	case NBSCrypto_HASH_SIMD_256:			{r=&simd_256_desc;break;}
	case NBSCrypto_HASH_SIMD_384:			{r=&simd_384_desc;break;}
	case NBSCrypto_HASH_SIMD_512:			{r=&simd_512_desc;break;}
	case NBSCrypto_HASH_SM3:			{r=&sm3_desc;break;}
	case NBSCrypto_HASH_SNEFRU:			{r=&snefru_desc;break;}
	case NBSCrypto_HASH_STREEBOG_256:		{r=&streebog_256_desc;break;}
	case NBSCrypto_HASH_STREEBOG_512:		{r=&streebog_512_desc;break;}
	case NBSCrypto_HASH_SWIFFTX_224:		{r=&swifftx_224_desc;break;}
	case NBSCrypto_HASH_SWIFFTX_256:		{r=&swifftx_256_desc;break;}
	case NBSCrypto_HASH_SWIFFTX_384:		{r=&swifftx_384_desc;break;}
	case NBSCrypto_HASH_SWIFFTX_512:		{r=&swifftx_512_desc;break;}
	case NBSCrypto_HASH_TIGER1_128_3:		{r=&tiger1_128_3_desc;break;}
	case NBSCrypto_HASH_TIGER1_160_3:		{r=&tiger1_160_3_desc;break;}
	case NBSCrypto_HASH_TIGER1_192_3:		{r=&tiger1_192_3_desc;break;}
	case NBSCrypto_HASH_TIGER1_128_4:		{r=&tiger1_128_4_desc;break;}
	case NBSCrypto_HASH_TIGER1_160_4:		{r=&tiger1_160_4_desc;break;}
	case NBSCrypto_HASH_TIGER1_192_4:		{r=&tiger1_192_4_desc;break;}
	case NBSCrypto_HASH_TIGER2_128_3:		{r=&tiger2_128_3_desc;break;}
	case NBSCrypto_HASH_TIGER2_160_3:		{r=&tiger2_160_3_desc;break;}
	case NBSCrypto_HASH_TIGER2_192_3:		{r=&tiger2_192_3_desc;break;}
	case NBSCrypto_HASH_TIGER2_128_4:		{r=&tiger2_128_4_desc;break;}
	case NBSCrypto_HASH_TIGER2_160_4:		{r=&tiger2_160_4_desc;break;}
	case NBSCrypto_HASH_TIGER2_192_4:		{r=&tiger2_192_4_desc;break;}
	case NBSCrypto_HASH_WHIRLPOOL:			{r=&whirlpool_desc;break;}
#if !TARGET_OS_WATCH
	case NBSCrypto_HASH_XXH_32:			{r=&xxh_32_desc;break;}
	case NBSCrypto_HASH_XXH_64:			{r=&xxh_64_desc;break;}
	case NBSCrypto_HASH_XXH3_64:			{r=&xxh3_64_desc;break;}
	case NBSCrypto_HASH_XXH3_128:			{r=&xxh3_128_desc;break;}
#endif
	default:					{r=&sha3_512_desc;break;}
    }
    unregister_hash(r);
    return r;
}

- (NSString*)_paddingString:(NSString*)s withLength:(unsigned long)sl{
    if(s.length<sl | s.length>sl){
	return [s stringByPaddingToLength:sl withString:[_HEX_PADDING objectAtIndex:0] startingAtIndex:0];
    }
    return s;
}

- (NSString*)_hashData:(NSData*)d{
    NSMutableString *r;

    register_hash([self _getHashDescriptor]);

    unsigned char h[hash_descriptor[0].hashsize];

    switch (_mac) {
	case NBSCrypto_MAC_HMAC:{
	    NSString *sKEY=[_key stringByAppendingString:[_HEX_PADDING objectAtIndex:0]];

	    if (_key.length >= hash_descriptor[0].blocksize) {
		sKEY = _key;
	    }else{
		sKEY = [self _paddingString:sKEY withLength:hash_descriptor[0].blocksize];
	    }

	    hmac_state s;
	    hmac_init(hash_descriptor[0].ID, (const unsigned char *)[sKEY UTF8String], sKEY.length, &s);
	    hmac_process(d.bytes, d.length, &s);
	    hmac_done(h, &hash_descriptor[0].hashsize, &s);
	    break;
	}
	case NBSCrypto_MAC_POLY1305:{
	    NSString *sKEY=[_key stringByAppendingString:[_HEX_PADDING objectAtIndex:0]];
	    sKEY = [self _paddingString:sKEY withLength:_BIT_LENGTH_256];

	    unsigned char out[_BIT_LENGTH_128];

	    poly1305_state s;
	    poly1305_init((const unsigned char *)[sKEY UTF8String], &s);
	    poly1305_process(d.bytes, d.length, &s);
	    poly1305_done(out, &s);

	    NSMutableString *pr;
	    pr=[NSMutableString stringWithCapacity:_BIT_LENGTH_128*2];
	    for(int i=0;i<_BIT_LENGTH_128;i++){[pr appendFormat:@"%02x",out[i]];}
	    return pr;

	    break;
	}

	default:{
	    hash_state s;
	    hash_descriptor[0].init(&s);
	    hash_descriptor[0].process(&s, d.bytes, d.length);
	    hash_descriptor[0].done(&s, h);
	    break;
	}
    }

    r=[NSMutableString stringWithCapacity:hash_descriptor[0].hashsize*2];
    for(int i=0;i<hash_descriptor[0].hashsize;i++){[r appendFormat:@"%02x",h[i]];}

    unregister_hash([self _getHashDescriptor]);

    return r;
}

- (instancetype)init{
    self = [super init];
    if(self){
	_algorithm = NBSCrypto_HASH_SHA3_512;
	_key = @"";
	_mac = NBSCrypto_MAC_NONE;
    }
    return self;
}

- (void)dealloc{
    unregister_hash([self _getHashDescriptor]);
    _algorithm = NBSCrypto_HASH_SHA3_512;
    _key = @"";
    _mac = NBSCrypto_MAC_NONE;
}

- (void)setAlgorithm:(NBSCrypto_HASH)ALGORITHM{
    _algorithm=ALGORITHM;
}

- (void)useMAC:(NBSCrypto_MAC)MAC{
    _mac = MAC;
}

- (void)setKey:(NSString *)KEY{
    _key = KEY;
}

- (NSString*)hashData:(NSData*)d{
    return [self _hashData:d];
}

-(NSString*)hashString:(NSString*)s{
    NSData*d=[s dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    return [self _hashData:d];
}




+(NSString*)hashString:(NSString*)s{
    return [self hashString:s withAlgorithm:0 useMAC:NBSCrypto_MAC_NONE setKeyForMAC:@""];
}

+(NSString*)hashString:(NSString*)s withAlgorithm:(NBSCrypto_HASH)a{
    return [self hashString:s withAlgorithm:a useMAC:NBSCrypto_MAC_NONE setKeyForMAC:@""];
}

+(NSString*)hashString:(NSString*)s withAlgorithm:(NBSCrypto_HASH)a useMAC:(NBSCrypto_MAC)m setKeyForMAC:(NSString*)k{
    NBSCryptoHash *r = [[self alloc] init];
    [r setAlgorithm:a];
    [r useMAC:m];
    if (m) {
	[r setKey:k];
    }
    return [r hashString:s];
}

@end
