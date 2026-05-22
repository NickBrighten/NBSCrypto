//
//	NBSCryptoBases.m
//	NBSCrypto
//

#import "NBSCryptoBases.h"
#import "NBSCryptoDefines_Internal.h"
#import "nbs_crypto.h"


@implementation NBSCryptoBases


#pragma mark - BASE-CONVERT
+(NSString*)baseConvert:(NSString*)s fromBase:(NBSCrypto_BASE)fB toBase:(NBSCrypto_BASE)tB{
    if(fB<NBSCrypto_BASE_BINARY || fB>NBSCrypto_BASE_DUOSEXAGESIMAL || tB<NBSCrypto_BASE_BINARY || tB>NBSCrypto_BASE_DUOSEXAGESIMAL){printf(_WARNING_BASE);}
    fB=(fB<NBSCrypto_BASE_BINARY)?NBSCrypto_BASE_BINARY:fB;
    fB=(fB>NBSCrypto_BASE_DUOSEXAGESIMAL)?NBSCrypto_BASE_DUOSEXAGESIMAL:fB;
    tB=(tB<NBSCrypto_BASE_BINARY)?NBSCrypto_BASE_BINARY:tB;
    tB=(tB>NBSCrypto_BASE_DUOSEXAGESIMAL)?NBSCrypto_BASE_DUOSEXAGESIMAL:tB;

    char *b;
    if (fB<=32) {
	b=basetobase([[s uppercaseString] UTF8String], fB, tB);
    }else{
	b=basetobase([s UTF8String], fB, tB);
    }

    return [NSString stringWithCString:b encoding:NSUTF8StringEncoding];
}




#pragma mark - BASE-ENCODE
+(NSString*)base16_encode:(NSString*)s mode:(NBSCrypto_BASE16MODE)m{
    NSData *d=[s dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    unsigned long oL=d.length+(d.length/3)+d.length;
    char o[oL];

    if(m<NBSCrypto_BASE16MODE_LOWERCASE || m>NBSCrypto_BASE16MODE_UPPERCASE){printf(_WARNING_Base16Encode);}
    m=(m<=NBSCrypto_BASE16MODE_LOWERCASE)?NBSCrypto_BASE16MODE_LOWERCASE:NBSCrypto_BASE16MODE_UPPERCASE;
    base16_encode(d.bytes, d.length, o, &oL, (int)m);
    return [NSString stringWithCString:o encoding:NSUTF8StringEncoding];
}

+ (NSString*)base32_encode:(NSString*)s mode:(NBSCrypto_BASE32MODE)m{
    NSData *d=[s dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    unsigned long oL=d.length+(d.length/3)+d.length;
    char o[oL];

    if(m<NBSCrypto_BASE32MODE_RFC4648 || m>NBSCrypto_BASE32MODE_CROCKFORD){printf(_WARNING_Base32Encode);}
    m=(m<NBSCrypto_BASE32MODE_RFC4648)?NBSCrypto_BASE32MODE_RFC4648:m;
    m=(m>NBSCrypto_BASE32MODE_CROCKFORD)?NBSCrypto_BASE32MODE_CROCKFORD:m;

    base32_encode(d.bytes, d.length, o, &oL, (int)m);
    return [NSString stringWithCString:o encoding:NSUTF8StringEncoding];
}

+ (NSString*)base64_encode:(NSString*)s mode:(NBSCrypto_BASE64MODE)m{
    NSData *d=[s dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    unsigned long oL=d.length+(d.length/3)+d.length;
    char o[oL];

    if(m<NBSCrypto_BASE64MODE_DEFAULT || m>NBSCrypto_BASE64MODE_RFC4648_STRICT){printf(_WARNING_Base64Encode);}
    m=(m<NBSCrypto_BASE64MODE_DEFAULT)?NBSCrypto_BASE64MODE_DEFAULT:m;
    m=(m>NBSCrypto_BASE64MODE_RFC4648_STRICT)?NBSCrypto_BASE64MODE_RFC4648_STRICT:m;

    switch(m){
	case NBSCrypto_BASE64MODE_DEFAULT:{
	    base64_encode(d.bytes, d.length, o, &oL);
	    break;
	}
	case NBSCrypto_BASE64MODE_RFC4648:{
	    base64url_encode(d.bytes, d.length, o, &oL);
	    break;
	}
	case NBSCrypto_BASE64MODE_RFC4648_STRICT:{
	    base64url_strict_encode(d.bytes, d.length, o, &oL);
	    break;
	}
    }
    return [NSString stringWithCString:o encoding:NSUTF8StringEncoding];
}




#pragma mark - BASE-DECODE
+ (NSString*)base16_decode:(NSString*)s{
    NSData *d=[s dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    unsigned long oL=d.length+(d.length/3)+d.length;
    char o[oL];
    base16_decode(d.bytes, d.length, o, &oL);
    NSMutableString *r;
    r=[NSMutableString stringWithCapacity:oL*2];
    for(int i=0;i<oL;i++){[r appendFormat:@"%c", o[i]];}
    return r;
}

+ (NSString*)base32_decode:(NSString*)s mode:(NBSCrypto_BASE32MODE)m{
    NSData *d=[s dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    unsigned long oL=d.length+(d.length/3)+d.length;
    unsigned char o[oL];

    if(m<NBSCrypto_BASE32MODE_RFC4648 || m>NBSCrypto_BASE32MODE_CROCKFORD){printf(_WARNING_Base32Decode);}
    m=(m<NBSCrypto_BASE32MODE_RFC4648)?NBSCrypto_BASE32MODE_RFC4648:m;
    m=(m>NBSCrypto_BASE32MODE_CROCKFORD)?NBSCrypto_BASE32MODE_CROCKFORD:m;

    base32_decode(d.bytes, d.length, o, &oL, (int)m);
    NSMutableString *r;
    r=[NSMutableString stringWithCapacity:oL*2];
    for(int i=0;i<oL;i++){[r appendFormat:@"%c", o[i]];}
    return r;
}

+ (NSString*)base64_decode:(NSString*)s mode:(NBSCrypto_BASE64MODE)m{
    NSData *d=[s dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    unsigned long oL=d.length+(d.length/3)+d.length;
    unsigned char o[oL];

    if(m<NBSCrypto_BASE64MODE_DEFAULT || m>NBSCrypto_BASE64MODE_RFC4648_STRICT){printf(_WARNING_Base64Decode);}
    m=(m<NBSCrypto_BASE64MODE_DEFAULT)?NBSCrypto_BASE64MODE_DEFAULT:m;
    m=(m>NBSCrypto_BASE64MODE_RFC4648_STRICT)?NBSCrypto_BASE64MODE_RFC4648_STRICT:m;

    switch(m){
	case NBSCrypto_BASE64MODE_DEFAULT:{
	    base64_decode(d.bytes, d.length, o, &oL);
	    break;
	}
	case NBSCrypto_BASE64MODE_RFC4648:{
	    base64url_decode(d.bytes, d.length, o, &oL);
	    break;
	}
	case NBSCrypto_BASE64MODE_RFC4648_STRICT:{
	    base64url_strict_decode(d.bytes, d.length, o, &oL);
	    break;
	}
    }
    NSMutableString *r;
    r=[NSMutableString stringWithCapacity:oL*2];
    for(int i=0;i<oL;i++){[r appendFormat:@"%c", o[i]];}
    return r;
}


@end
