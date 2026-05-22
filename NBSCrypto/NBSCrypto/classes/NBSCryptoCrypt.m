//
//	NBSCryptoCrypt.m
//	NBSCrypto
//

#import "NBSCryptoCrypt.h"
#import "NBSCryptoCrypt_Internal.h"
#import "nbs_crypto.h"


@implementation NBSCryptoCrypt


NSUInteger bitLength;
NSUInteger mode;


@synthesize INPUTFORMAT				= _inputformat;
@synthesize OUTPUTFORMAT			= _outputformat;
@synthesize ALGORITHM				= _algorithm;
@synthesize KEY					= _key;
@synthesize KEY2				= _key2;
@synthesize IV					= _iv;
@synthesize AAD					= _aad;
@synthesize TAG					= _tag;


- (const struct cipher_descriptor*)_getCipherDescriptor{
    const struct cipher_descriptor* r = NULL;

    for (int i=0; i<(sizeof(_CIPHER_PRESETS)/16); i++) {
	if (_CIPHER_PRESETS[i][0] == _algorithm) {
	    switch (_CIPHER_PRESETS[i][1]) {
		case _CIPHER_AES:		{r=&aes_desc;break;}
		case _CIPHER_ANUBIS:		{r=&anubis_desc;break;}
		case _CIPHER_ANUBIS_TWEAK:	{r=&anubis_tweak_desc;break;}
		case _CIPHER_ARIA:		{r=&aria_desc;break;}
		case _CIPHER_BLOWFISH:		{r=&blowfish_desc;break;}
		case _CIPHER_CAMELLIA:		{r=&camellia_desc;break;}
		case _CIPHER_CAST5:		{r=&cast5_desc;break;}
		case _CIPHER_CAST6:		{r=&cast6_desc;break;}
		case _CIPHER_CHACHA:		{r=&chacha_desc;break;}
		case _CIPHER_DES:		{r=&des_desc;break;}
		case _CIPHER_DES3:		{r=&des3_desc;break;}
		case _CIPHER_IDEA:		{r=&idea_desc;break;}
		case _CIPHER_KASUMI:		{r=&kasumi_desc;break;}
		case _CIPHER_KHAZAD:		{r=&khazad_desc;break;}
		case _CIPHER_LEA:		{r=&lea_desc;break;}
		case _CIPHER_MARS:		{r=&mars_desc;break;}
		case _CIPHER_NOEKEON:		{r=&noekeon_desc;break;}
		case _CIPHER_PRESENT:		{r=&present_desc;break;}
		case _CIPHER_RC2:		{r=&rc2_desc;break;}
		case _CIPHER_RC4:		{r=&rc4_desc;break;}
		case _CIPHER_RC6:		{r=&rc6_desc;break;}
		case _CIPHER_SAFER_K64:		{r=&safer_k64_desc;break;}
		case _CIPHER_SAFER_K128:	{r=&safer_k128_desc;break;}
		case _CIPHER_SAFER_SK64:	{r=&safer_sk64_desc;break;}
		case _CIPHER_SAFER_SK128:	{r=&safer_sk128_desc;break;}
		case _CIPHER_SAFER_PLUS:	{r=&saferp_desc;break;}
		case _CIPHER_SEED:		{r=&seed_desc;break;}
		case _CIPHER_SERPENT:		{r=&serpent_desc;break;}
		case _CIPHER_SKIPJACK:		{r=&skipjack_desc;break;}
		case _CIPHER_SM4:		{r=&sm4_desc;break;}
		case _CIPHER_TEA:		{r=&tea_desc;break;}
		case _CIPHER_TWOFISH:		{r=&twofish_desc;break;}
		case _CIPHER_XTEA:		{r=&xtea_desc;break;}
		default:			{r=&aes_desc;break;}
	    }
	    unregister_cipher(r);
	    bitLength = _CIPHER_PRESETS[i][2];
	    mode = _CIPHER_PRESETS[i][3];
	}
    }
    return r;
}

- (NSString*)_paddingString:(NSString*)s withLength:(unsigned long)sl{
    if(s.length<sl | s.length>sl){
	return [s stringByPaddingToLength:sl withString:[_HEX_PADDING objectAtIndex:0] startingAtIndex:0];
    }
    return s;
}

- (NSString*)_stringFromChar:(unsigned char*)s withLength:(unsigned long)sl delHStr:(BOOL)hs{
    NSString *r;
    NSMutableString *mr=[NSMutableString stringWithCapacity:sl];
    for(int i=0;i<sl;i++){[mr appendFormat:@"%c", s[i]];}
    if([mr stringByRemovingPercentEncoding]){
	switch ((int)hs) {
	    case 0:{
		r=[NSString stringWithString:[mr stringByRemovingPercentEncoding]];
		break;
	    }
	    case 1:{
		for(int i=0;i<_HEX_PADDING.count;i++){
		    if([mr containsString:[_HEX_PADDING objectAtIndex:i]]){
			r=[mr stringByReplacingOccurrencesOfString:[_HEX_PADDING objectAtIndex:i] withString:@""];
		    }
		}
	    }
	}
    }
    mr=NULL;
    return r;
}

- (NSString*)_base64FromChar:(const unsigned char*)s withLength:(unsigned long)sl{
    unsigned long oL=sl*2;
    char o[oL];
    base64_encode(s, sl, o, &oL);
    return [NSString stringWithCString:o encoding:NSUTF8StringEncoding];
}

- (NSString*)_hexFromChar:(const unsigned char*)s withLength:(unsigned long)sl{
    NSMutableString *hr;
    hr=[NSMutableString stringWithCapacity:sl*2];
    for(int i=0;i<sl;i++){
	[hr appendFormat:@"%02x",s[i]];
    }
    return hr;
}

- (NSString*)_charFromHex:(NSString*)str{
    NSMutableString *cr = [[NSMutableString alloc] init];
    int i = 0;
    while (i < ([str length]) )
    {
	NSString *hC = [str substringWithRange: NSMakeRange(i, 2)];
	int v = 0;
	sscanf([hC cStringUsingEncoding:NSUTF8StringEncoding], "%x", &v);
	[cr appendFormat:@"%c", (char)v];
	i+=2;
    }
    return cr;
}

const unsigned char* _charFromHex(const char* str)
{
    char* cs = (char*)malloc(strlen(str));
    int i=0;
    while (i < (strlen(str))) {
	char *h = (char*)malloc(2);
	strncpy(h, str+i, 2);
	int v=0;
	sscanf(h, "%x", &v);
	strcat(cs, (char*)&v);
	i+=2;
    }
    return (const unsigned char*)cs;
}

- (unsigned long)_determineLengthFromData:(NSData*)data withBlockLength:(double)blockLength isBlock:(BOOL)isBlock{
    unsigned long r;

    if(isBlock){
	r=(((double)data.length/(double)blockLength)==(int)((double)data.length/(double)blockLength))?(ceil((double)data.length/((double)blockLength-1))*(double)blockLength)-blockLength:(ceil((double)data.length/(double)blockLength)*(double)blockLength);
    }else{
	r=(((double)data.length/(double)blockLength)==(int)((double)data.length/(double)blockLength))?(ceil((double)data.length/((double)blockLength-1))*(double)blockLength):(ceil((double)data.length/(double)blockLength)*(double)blockLength);
    }

    return r;
}

- (NSString*)_edc:(NSString*)string eod:(BOOL)eod{
    const struct cipher_descriptor *cD = [self _getCipherDescriptor];
    NSString *r=@"";

    NSData *dTE=[string dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    NSString *sKEY=[_key stringByAppendingString:[_HEX_PADDING objectAtIndex:0]];
    NSString *sIV=[_iv stringByAppendingString:[_HEX_PADDING objectAtIndex:0]];
    NSString *sAAD=[_aad stringByAppendingString:[_HEX_PADDING objectAtIndex:0]];

    //HANDLE KEY1 AND KEY2
    NSString *sKEY1 = [self _paddingString:sKEY withLength:bitLength];
    NSString *sKEY2;
    if (_key2.length > 0) {
	//IF KEY2 IS SET
	sKEY2 = [self _paddingString:_key2 withLength:bitLength];
    }else{
	//GENERATE KEY2 FROM KEY
	sKEY2 = (sKEY.length > bitLength)?[self _paddingString:[sKEY substringWithRange:NSMakeRange(bitLength, sKEY.length-bitLength)] withLength:bitLength]:[self _paddingString:@"" withLength:bitLength];
    }

    //HANDLE sKEY
    if( ([self _getCipherDescriptor] == &blowfish_desc) | ([self _getCipherDescriptor] == &cast5_desc) | ([self _getCipherDescriptor] == &rc2_desc) | ([self _getCipherDescriptor] == &rc4_desc) | ([self _getCipherDescriptor] == &rc6_desc) ){
	//BLOWFISH, CAST5, RC2, RC4, RC6
	if(_key.length < cipher_descriptor[0].min_key_length){
	    sKEY = [self _paddingString:sKEY withLength:(unsigned long)cipher_descriptor[0].min_key_length];
	}else if(_key.length > cipher_descriptor[0].max_key_length){
	    sKEY = [self _paddingString:sKEY withLength:(unsigned long)cipher_descriptor[0].max_key_length];
	}else{
	    sKEY = [self _paddingString:sKEY withLength:(unsigned long)_key.length];
	}
    }else{
	//ALL OTHER CIPHERS
	sKEY = [self _paddingString:sKEY withLength:bitLength];
    }


    //HANDLE BLOCK-MODES AND STREAM-MODES
    if ((mode == _CIPHER_MODE_CCM) | (mode == _CIPHER_MODE_EAX) | (mode == _CIPHER_MODE_GCM) | (mode == _CIPHER_MODE_OCB3) | (mode == _CIPHER_MODE_CHACHA8POLY1305) | (mode == _CIPHER_MODE_CHACHA12POLY1305) | (mode == _CIPHER_MODE_CHACHA20POLY1305)) {
	//STREAM-MODES
	if ((mode == _CIPHER_MODE_CHACHA8POLY1305) | (mode == _CIPHER_MODE_CHACHA12POLY1305) | (mode == _CIPHER_MODE_CHACHA20POLY1305)) {
	    if (_iv.length <= _BIT_LENGTH_64) {
		sIV = [self _paddingString:sIV withLength:_BIT_LENGTH_64];
	    }else if (_iv.length <= _BIT_LENGTH_96){
		sIV = [self _paddingString:sIV withLength:_BIT_LENGTH_96];
	    }else if(_iv.length >= _BIT_LENGTH_128){
		sIV = [self _paddingString:sIV withLength:_BIT_LENGTH_128];
	    }
	    sAAD = [self _paddingString:sAAD withLength:_aad.length];
	}else{
	    sIV = [self _paddingString:sIV withLength:_iv.length];
	    sAAD = [self _paddingString:sAAD withLength:_aad.length];
	}
    }else{
	//BLOCK-MODES
	sIV = [self _paddingString:sIV withLength:(unsigned long)cipher_descriptor[0].block_length];
    }

    register_cipher([self _getCipherDescriptor]);

    switch (mode) {
#pragma mark CBC
	case _CIPHER_MODE_CBC:{
	    cm_CBC m;
	    cbc_start(0, (const unsigned char *)[sIV UTF8String], (const unsigned char *)[sKEY UTF8String], (int)sKEY.length, 0, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		cbc_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:true];
	    }else{
		unsigned long eTL;
		if(!((int)string.length % (int)cipher_descriptor[0].block_length)){
		    eTL = [self _determineLengthFromData:dTE withBlockLength:cipher_descriptor[0].block_length isBlock:NO];
		}else{
		    eTL = [self _determineLengthFromData:dTE withBlockLength:cipher_descriptor[0].block_length isBlock:YES];
		}
		unsigned char eT[eTL];
		NSString *sTE=[string stringByPaddingToLength:eTL withString:[_HEX_PADDING objectAtIndex:((unsigned long)eTL-(unsigned long)dTE.length)] startingAtIndex:0];
		cbc_encrypt((const unsigned char *)[sTE UTF8String], eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

		sTE=NULL;
	    }

	    cbc_done(&m);
	    break;
	}
#pragma mark CCM
	case _CIPHER_MODE_CCM:{
	    cm_CCM m;

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];

		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];

		ccm_start(0, (const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, dTL, (unsigned long)taglen, (unsigned long)sAAD.length, &m);
		ccm_add_nonce((const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, &m);
		ccm_add_aad((const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, &m);
		ccm_decrypt(eT, dT, dTL, &m);
		ccm_done(tag, &taglen, &m);

		if ([[self _base64FromChar:tag withLength:taglen] isEqual:[self getTAG]]) {
		    r = [self _stringFromChar:dT withLength:dTL delHStr:false];
		}else{
		    r=0;
		}
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];

		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];

		ccm_start(0, (const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, eTL, (unsigned long)taglen, (unsigned long)sAAD.length, &m);
		ccm_add_nonce((const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, &m);
		ccm_add_aad((const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, &m);
		ccm_encrypt((unsigned char*)dTE.bytes, eT, eTL, &m);
		ccm_done(tag, &taglen, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			[self setTAG:[self _base64FromChar:tag withLength:taglen]];
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			[self setTAG:[self _hexFromChar:tag withLength:taglen]];
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    break;
	}
#pragma mark CFB
	case _CIPHER_MODE_CFB:{
	    cm_CFB m;
	    cfb_start(0, (const unsigned char *)[sIV UTF8String], (const unsigned char *)[sKEY UTF8String], (int)sKEY.length, 0, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		cfb_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		cfb_encrypt(dTE.bytes, eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    cfb_done(&m);
	    break;
	}
#pragma mark CTR
	case _CIPHER_MODE_CTR:{
	    cm_CTR m;
	    ctr_start(0, (const unsigned char *)[sIV UTF8String], (const unsigned char *)[sKEY UTF8String], (int)sKEY.length, 0, CTR_COUNTER_BIG_ENDIAN, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		ctr_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		ctr_encrypt(dTE.bytes, eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    ctr_done(&m);
	    break;
	}
#pragma mark EAX
	case _CIPHER_MODE_EAX:{
	    cm_EAX m;

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];

		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];

		eax_start(0, (const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, (const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, &m);
		eax_decrypt(eT, dT, dTL, &m);
		eax_done(tag, &taglen, &m);

		if ([[self _base64FromChar:tag withLength:taglen] isEqual:[self getTAG]]) {
		    r = [self _stringFromChar:dT withLength:dTL delHStr:false];
		}else{
		    r=0;
		}
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];

		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];

		eax_start(0, (const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, (const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, &m);
		eax_encrypt((unsigned char*)dTE.bytes, eT, eTL, &m);
		eax_done(tag, &taglen, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			[self setTAG:[self _base64FromChar:tag withLength:taglen]];
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			[self setTAG:[self _hexFromChar:tag withLength:taglen]];
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    break;
	}
#pragma mark ECB
	case _CIPHER_MODE_ECB:{
	    cm_ECB m;
	    ecb_start(0, (const unsigned char *)[sKEY UTF8String], (int)sKEY.length, 0, &m);

	    if (eod) {
		switch (_inputformat) {
		    case 1:{ //BASE64
			unsigned long eTL = dTE.length;
			unsigned char eT[eTL];
			base64_decode(dTE.bytes, dTE.length, eT, &eTL);

			unsigned long dTL=eTL;
			unsigned char dT[dTL];
			ecb_decrypt(eT, dT, dTL, &m);

			r = [self _stringFromChar:dT withLength:dTL delHStr:true];

			break;
		    }
		    case 2:{ //HEX
			unsigned long eTL = dTE.length / 2;
			const unsigned char *eT = _charFromHex(dTE.bytes);

			NSLog(@"%s", eT);

			unsigned long dTL=eTL;
			unsigned char dT[dTL];
			ecb_decrypt(eT, dT, dTL, &m);

			r = [self _stringFromChar:dT withLength:dTL delHStr:true];

			break;
		    }
		}
	    }else{
		unsigned long eTL;
		if(!((int)string.length % (int)cipher_descriptor[0].block_length)){
		    eTL = [self _determineLengthFromData:dTE withBlockLength:cipher_descriptor[0].block_length isBlock:NO];
		}else{
		    eTL = [self _determineLengthFromData:dTE withBlockLength:cipher_descriptor[0].block_length isBlock:YES];
		}
		unsigned char eT[eTL];
		NSString *sTE=[string stringByPaddingToLength:eTL withString:[_HEX_PADDING objectAtIndex:((unsigned long)eTL-(unsigned long)dTE.length)] startingAtIndex:0];
		ecb_encrypt((const unsigned char *)[sTE UTF8String], eT, eTL, &m);

		//NSLog(@"%s", eT);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    ecb_done(&m);

	    break;
	}
#pragma mark F8
	case _CIPHER_MODE_F8:{
	    cm_F8 m;
	    f8_start(0, (const unsigned char *)[sIV UTF8String], (const unsigned char *)[sKEY UTF8String], (int)sKEY.length, (const unsigned char *)(const unsigned char *)[sKEY2 UTF8String], (int)sKEY2.length, 0, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		f8_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		f8_encrypt(dTE.bytes, eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    f8_done(&m);

	    break;
	}
#pragma mark GCM
	case _CIPHER_MODE_GCM:{
	    cm_GCM m;
	    gcm_start(0, (const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, 0, &m);
	    gcm_add_iv((const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, &m);
	    gcm_add_aad((const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		gcm_decrypt(eT, dT, dTL, &m);

		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];
		gcm_done(tag, &taglen, &m);

		if ([[self _base64FromChar:tag withLength:taglen] isEqual:[self getTAG]]) {
		    r = [self _stringFromChar:dT withLength:dTL delHStr:false];
		}else{
		    r=0;
		}
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		gcm_encrypt((unsigned char*)dTE.bytes, eT, eTL, &m);

		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];
		gcm_done(tag, &taglen, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			[self setTAG:[self _base64FromChar:tag withLength:taglen]];
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			[self setTAG:[self _hexFromChar:tag withLength:taglen]];
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    break;
	}
#pragma mark LRW
	case _CIPHER_MODE_LRW:{
	    cm_LRW m;
	    lrw_start(0, (const unsigned char *)[sIV UTF8String], (const unsigned char *)[sKEY1 UTF8String], (const unsigned char *)[sKEY2 UTF8String], (int)sKEY1.length, 0, &m);
	    lrw_add_iv((const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		lrw_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		lrw_encrypt((unsigned char*)dTE.bytes, eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    lrw_done(&m);

	    break;
	}
#pragma mark OCB
	case _CIPHER_MODE_OCB:{
	    cm_OCB m;
	    ocb_start(0, (const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		ocb_decrypt(eT, dT, &m);

		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];
		ocb_done(eT, dT, 0, tag, &taglen, 1, &m);

		if ([[self _base64FromChar:tag withLength:taglen] isEqual:[self getTAG]]) {
		    r = [self _stringFromChar:dT withLength:dTL delHStr:false];
		}else{
		    r=0;
		}
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		ocb_encrypt(dTE.bytes, eT, &m);

		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];
		ocb_done(dTE.bytes, eT, 0, tag, &taglen, 0, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			[self setTAG:[self _base64FromChar:tag withLength:taglen]];
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			[self setTAG:[self _hexFromChar:tag withLength:taglen]];
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    break;
	}
#pragma mark OCB3
	case _CIPHER_MODE_OCB3:{
	    cm_OCB3 m;

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];

		ocb3_start(0, (const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, taglen, &m);
		ocb3_add_aad((const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, &m);
		ocb3_decrypt(eT, dT, dTL, &m);
		ocb3_done(tag, &taglen, &m);

		if ([[self _base64FromChar:tag withLength:taglen] isEqual:[self getTAG]]) {
		    r = [self _stringFromChar:dT withLength:dTL delHStr:false];
		}else{
		    r=0;
		}
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		unsigned long taglen = cipher_descriptor[0].block_length;
		unsigned char tag[taglen];

		ocb3_start(0, (const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, taglen, &m);
		ocb3_add_aad((const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, &m);
		ocb3_encrypt(dTE.bytes, eT, eTL, &m);
		ocb3_done(tag, &taglen, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			[self setTAG:[self _base64FromChar:tag withLength:taglen]];
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			[self setTAG:[self _hexFromChar:tag withLength:taglen]];
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    break;
	}
#pragma mark OFB
	case _CIPHER_MODE_OFB:{
	    cm_OFB m;
	    ofb_start(0, (const unsigned char *)[sIV UTF8String], (const unsigned char *)[sKEY UTF8String], (int)sKEY.length, 0, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		ofb_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		ofb_encrypt(dTE.bytes, eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    ofb_done(&m);
	    break;
	}
#pragma mark XTS
	case _CIPHER_MODE_XTS:{
	    cm_XTS m;
	    xts_start(0, (const unsigned char *)[sKEY1 UTF8String], (const unsigned char *)[sKEY2 UTF8String], (int)sKEY1.length, 0, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		xts_decrypt(eT, dT, dTL, (unsigned char *)[sIV UTF8String], &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		xts_encrypt(dTE.bytes, eT, eTL, (unsigned char *)[sIV UTF8String], &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    xts_done(&m);
	    break;
	}
#pragma mark CHACHA8
	case _CIPHER_MODE_CHACHA8:{
	    cipher_state m;

	    chacha_setup((const unsigned char *)[sKEY UTF8String], (int)sKEY.length, (const unsigned char *)[sIV UTF8String], (int)sIV.length, 8, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		chacha_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		chacha_encrypt(dTE.bytes, eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    chacha_done(&m);
	    break;
	}
#pragma mark CHACHA12
	case _CIPHER_MODE_CHACHA12:{
	    cipher_state m;

	    chacha_setup((const unsigned char *)[sKEY UTF8String], (int)sKEY.length, (const unsigned char *)[sIV UTF8String], (int)sIV.length, 12, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		chacha_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		chacha_encrypt(dTE.bytes, eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    chacha_done(&m);
	    break;
	}
#pragma mark CHACHA20
	case _CIPHER_MODE_CHACHA20:{
	    cipher_state m;

	    chacha_setup((const unsigned char *)[sKEY UTF8String], (int)sKEY.length, (const unsigned char *)[sIV UTF8String], (int)sIV.length, 20, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		chacha_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		chacha_encrypt(dTE.bytes, eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    chacha_done(&m);
	    break;
	}
#pragma mark CHACHA8POLY1305
	case _CIPHER_MODE_CHACHA8POLY1305:{

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		unsigned long taglen = _BIT_LENGTH_128;
		unsigned char tag[taglen];

		chacha8poly1305_decrypt((const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, (const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, eT, dT, dTL, tag, taglen);

		if ([[self _base64FromChar:tag withLength:taglen] isEqual:[self getTAG]]) {
		    r = [self _stringFromChar:dT withLength:dTL delHStr:false];
		}else{
		    r=0;
		}
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		unsigned long taglen = _BIT_LENGTH_128;
		unsigned char tag[taglen];

		chacha8poly1305_encrypt((const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, (const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, dTE.bytes, eT, eTL, tag, taglen);

		switch (_outputformat) {
		    case 1:{ //BASE64
			[self setTAG:[self _base64FromChar:tag withLength:taglen]];
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			break;
		    }
		}

	    }

	    break;
	}
#pragma mark CHACHA12POLY1305
	case _CIPHER_MODE_CHACHA12POLY1305:{

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		unsigned long taglen = _BIT_LENGTH_128;
		unsigned char tag[taglen];

		chacha12poly1305_decrypt((const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, (const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, eT, dT, dTL, tag, taglen);

		if ([[self _base64FromChar:tag withLength:taglen] isEqual:[self getTAG]]) {
		    r = [self _stringFromChar:dT withLength:dTL delHStr:false];
		}else{
		    r=0;
		}
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		unsigned long taglen = _BIT_LENGTH_128;
		unsigned char tag[taglen];

		chacha12poly1305_encrypt((const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, (const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, dTE.bytes, eT, eTL, tag, taglen);

		switch (_outputformat) {
		    case 1:{ //BASE64
			[self setTAG:[self _base64FromChar:tag withLength:taglen]];
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			break;
		    }
		}

	    }

	    break;
	}
#pragma mark CHACHA20POLY1305
	case _CIPHER_MODE_CHACHA20POLY1305:{

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		unsigned long taglen = _BIT_LENGTH_128;
		unsigned char tag[taglen];

		chacha20poly1305_decrypt((const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, (const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, eT, dT, dTL, tag, taglen);

		if ([[self _base64FromChar:tag withLength:taglen] isEqual:[self getTAG]]) {
		    r = [self _stringFromChar:dT withLength:dTL delHStr:false];
		}else{
		    r=0;
		}
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		unsigned long taglen = _BIT_LENGTH_128;
		unsigned char tag[taglen];

		chacha20poly1305_encrypt((const unsigned char *)[sKEY UTF8String], (unsigned long)sKEY.length, (const unsigned char *)[sIV UTF8String], (unsigned long)sIV.length, (const unsigned char *)[sAAD UTF8String], (unsigned long)sAAD.length, dTE.bytes, eT, eTL, tag, taglen);

		switch (_outputformat) {
		    case 1:{ //BASE64
			[self setTAG:[self _base64FromChar:tag withLength:taglen]];
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			break;
		    }
		}

	    }

	    break;
	}
#pragma mark RC4
	case _CIPHER_MODE_RC4:{
	    cipher_state m;

	    rc4_setup((const unsigned char *)[sKEY UTF8String], (int)sKEY.length, 0, &m);

	    if (eod) {
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		base64_decode(dTE.bytes, dTE.length, eT, &eTL);

		unsigned long dTL=eTL;
		unsigned char dT[dTL];
		rc4_decrypt(eT, dT, dTL, &m);

		r = [self _stringFromChar:dT withLength:dTL delHStr:false];
	    }else{
		unsigned long eTL=dTE.length;
		unsigned char eT[eTL];
		rc4_encrypt(dTE.bytes, eT, eTL, &m);

		switch (_outputformat) {
		    case 1:{ //BASE64
			r = [self _base64FromChar:eT withLength:eTL];
			break;
		    }
		    case 2:{ //HEX
			r = [self _hexFromChar:eT withLength:eTL];
			break;
		    }
		}

	    }

	    rc4_done(&m);
	    break;
	}
    }

    unregister_cipher(cD);
    dTE = nil;
    sKEY = NULL;
    sKEY1 = NULL;
    sKEY2 = NULL;
    sIV = NULL;
    sAAD = NULL;

    return r;
}

- (instancetype)init{
    self = [super init];
    if(self){
	bitLength = 0;
	mode = _CIPHER_MODE_ECB;
	_inputformat = NBSCrypto_CIPHER_IO_BASE64;
	_outputformat = NBSCrypto_CIPHER_IO_BASE64;
	_algorithm = NBSCrypto_CIPHER_AES_128_ECB;
	_key = @"";
	_key2 = @"";
	_iv = @"";
	_aad = @"";
	_tag = @"";
    }
    return self;
}

- (void)dealloc{
    unregister_cipher([self _getCipherDescriptor]);

    bitLength = 0;
    mode = _CIPHER_MODE_ECB;
    _inputformat = NBSCrypto_CIPHER_IO_BASE64;
    _outputformat = NBSCrypto_CIPHER_IO_BASE64;
    _algorithm = NBSCrypto_CIPHER_AES_128_ECB;
    _key = @"";
    _key2 = @"";
    _iv = @"";
    _aad = @"";
    _tag = @"";
}

/*
- (void)setInputFormat:(NBSCrypto_CIPHER_IO)INPUTFORMAT{
    _inputformat=INPUTFORMAT;
}
 */

- (void)setOutputFormat:(NBSCrypto_CIPHER_IO)OUTPUTFORMAT{
    _outputformat=OUTPUTFORMAT;
}

- (void)setALGORITHM:(NBSCrypto_CIPHER)ALGORITHM{
    _algorithm=ALGORITHM;
}

- (void)setKEY:(NSString *)KEY{
    _key=KEY;
}

- (void)setKEY2:(NSString *)KEY2{
    _key2=KEY2;
}

- (void)setIV:(NSString *)IV{
    _iv=IV;
}

- (void)setAAD:(NSString *)AAD{
    _aad=AAD;
}

- (void)setTAG:(NSString *)TAG{
    _tag = TAG;
}

- (NSString *)getTAG{
    return _tag;
}

- (unsigned long)getIVLengthForCipher{
    NSUInteger r;
    register_cipher([self _getCipherDescriptor]);
    r=(mode!=_CIPHER_MODE_ECB)?cipher_descriptor[0].block_length:0;
    unregister_cipher([self _getCipherDescriptor]);
    return r;
}

- (NSString *)encryptString:(NSString *)string{
    return [self _edc:string eod:0];
}

- (NSString *)decryptString:(NSString *)string{
    return [self _edc:string eod:1];
}

@end
