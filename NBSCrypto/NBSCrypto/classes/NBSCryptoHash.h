//
//	NBSCryptoHash.h
//	NBSCrypto
//

#import <Foundation/Foundation.h>
#import "NBSCryptoDefines.h"


NS_ASSUME_NONNULL_BEGIN


///	NBSCryptoHash
///	@author			Nick Brighten
///	@copyright		© 2022-2026, NB-SYSTEMS, All rights reserved.
///	@version		1.0.0
///	@discussion		Conform to:
///				Institute of Electrical and Electronics Engineers (IEEE)			WORLDWIDE,
///				Internet Engineering Task Force (IETF)				WORLDWIDE,
///				National Institute of Standards and Technology (NIST)			USA,
///				European Network and Information Security Agency (ENISA)		EUROPE,
///				European Telecommunications Standards Institute (ETSI)		EUROPE,
///				Agence Nationale de la Sécurité des Systèmes D'information (ANSSI)	FRANCE,
///				Федеральная служба безопасности Российской Федерации (FSB)	RUSSIA,
///				Office of the State Commercial Cryptography Administration (OSCCA)	CHINA,
///				Korea Agency for Technology and Standards (KATS)			KOREA,
///				Korea Internet & Security Agency (KISA)				KOREA,
///				Japan Network Security Association (JNSA)				JAPAN,
///				Australian Cyber Security Centre (ACSC)				AUSTRALIA
///	@discussion		Compatible to openSSL, libtomcrypt, Crypto++, CPPCrypto, CycloneCRYPTO, PHP etc.
@interface NBSCryptoHash : NSObject


/// 	HASH-Algorithm (NBSCrypto_HASH) inclusive Bit-Length
///	@discussion		Set a HASH-Algorithm (NBSCrypto_HASH) for hashing/checksum/digit/HMAC
///	@discussion		The NBSCrypto_HASH include the Bit-Length
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
@property (nonatomic, setter=setAlgorithm:)	NBSCrypto_HASH ALGORITHM;


///	Using MAC
///	@discussion		useMAC set a MAC-Algorithm (NBSCrypto_MAC) for hashing/checksum/digit/HMAC
///	@discussion		A KEY is required for security reason
///	@discussion		If no KEY is specified, NBSCryptoHash automatically pads the KEY with zeros
///				to the required length.
@property (nonatomic, setter=useMAC:)		NBSCrypto_MAC MAC;


///	KEY (Required for HMAC)
///	@discussion		setKeyForMAC for hashing/checksum/digit/HMAC
///	@discussion		If no KEY is specified, NBSCryptoHash automatically pads the KEY with zeros
///				to the required length.
@property (nonatomic, setter=setKeyForMAC:)	NSString *KEY;


- (instancetype)init;


-(NSString*)hashData:(NSData*)data;


///	NBSCryptoHash -hashString
///	@discussion		Hashing/checksum/digit/HMAC a NSString in conjunction with the setted parameters
///	@param string		NSString to hashing/checksum/digit/HMAC
///	@return			NSString as hexadecimal
-(NSString*)hashString:(NSString*)string;


///	NBSCryptoHash +hashString:(NSString*)string
///	@discussion		Hashing/checksum/digit of an NSString in conjunction with default parameters
///	@discussion		DEFAULT-PARAMETERS:
///					Algorithm		: NBSCrypto_HASH_SHA3_512
///					useMAC		: NBSCrypto_MAC_NONE
///					setKeyForHMAC	: NULL
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@param string		NSString to hashing/checksum/digit/HMAC
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string;


///	NBSCryptoHash +hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm
///	@discussion		Hashing/checksum/digit of an NSString in conjunction with setted  parameters
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@param string		NSString to hashing/checksum/digit
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm;


///	NBSCryptoHash +hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm useHMAC:(BOOL)hmac setKeyForHMAC:(NSString*)hmacKey
///	@discussion		Hashing/checksum/digit/HMAC a NSString in conjunction with the setted parameters
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@discussion		If no KEY is specified, NBSCryptoHash automatically pads the KEY with zeros
///				to the required length.
///	@param string		NSString to hashing/checksum/digit/HMAC
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@param useMAC		The NBSCrypto_MAC which is used
///	@param macKey		Set the KEY for MAC
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm useMAC:(NBSCrypto_MAC)useMAC setKeyForMAC:(NSString*)macKey;


@end

NS_ASSUME_NONNULL_END
