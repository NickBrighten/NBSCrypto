//
//	NBSCryptoBases.h
//	NBSCrypto
//

#import <Foundation/Foundation.h>
#import "NBSCryptoDefines.h"


NS_ASSUME_NONNULL_BEGIN


///	NBSCryptoBases
///	@author			Nick Brighten
///	@copyright		© 2022-2026, NB-SYSTEMS, All rights reserved.
///	@version		1.0.0
@interface NBSCryptoBases : NSObject


#pragma mark - BASE-CONVERT
///	NBSCryptoBases - baseConvert
///	@discussion		Convert a base to another base
///	@param string		Base as NSString
///	@param fromBase		Base to become to convert, as NBSCrypto_BASE value
///	@param toBase		Base to convert, as NBSCrypto_BASE value
///	@returns		NSString
+(NSString*)baseConvert:(NSString*)string fromBase:(NBSCrypto_BASE)fromBase toBase:(NBSCrypto_BASE)toBase;


#pragma mark - BASE-ENCODE
///	NBSCryptoBases - base16_encode
///	@discussion		Encode an NSString to Base16
///	@param string		NSString to encode to Base16
///	@param mode		Base16 mode to encode as NBSCryptoBase_MODE_BASE16 value
///	@returns		NSString
+(NSString*)base16_encode:(NSString*)string mode:(NBSCrypto_BASE16MODE)mode;


///	NBSCryptoBases - base32_encode
///	@discussion		Encode an NSString to Base32
///	@param string		NSString to encode to Base32
///	@param mode		Base32 mode to encode as NBSCryptoBase_MODE_BASE32 value
///	@returns		NSString
+(NSString*)base32_encode:(NSString*)string mode:(NBSCrypto_BASE32MODE)mode;


///	NBSCryptoBases - base64_encode
///	@discussion		Encode an NSString to Base64
///	@param string		NSString to encode to Base64
///	@param mode		Base64 mode to encode as NBSCryptoBase_MODE_BASE64 value
///	@returns		NSString
+(NSString*)base64_encode:(NSString*)string mode:(NBSCrypto_BASE64MODE)mode;


#pragma mark - BASE-DECODE
///	NBSCryptoBases - base16_decode
///	@discussion		Decode a Base16 encoded NSString
///	@param string		Base16 encoded NSString to decode
///	@returns		NSString
+(NSString*)base16_decode:(NSString*)string;


///	NBSCryptoBases - base32_decode
///	@discussion		Decode a Base32 encoded NSString
///	@param string		Base32 encoded NSString to decode
///	@param mode		Base32 mode to decode as NBSCryptoBase_MODE_BASE32 value
///	@returns		NSString
+(NSString*)base32_decode:(NSString*)string mode:(NBSCrypto_BASE32MODE)mode;


///	NBSCryptoBases - base64_decode
///	@discussion		Decode a Base64 encoded NSString
///	@param string		Base64 encoded NSString to decode
///	@param mode		Base64 mode to decode as NBSCryptoBase_MODE_BASE64 value
///	@returns		NSString
+(NSString*)base64_decode:(NSString*)string mode:(NBSCrypto_BASE64MODE)mode;


@end

NS_ASSUME_NONNULL_END
