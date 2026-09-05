//
//	NBSCryptoHash.h
//	NBSCrypto
//

#import <Foundation/Foundation.h>
#import <NBSCrypto/NBSCryptoDefines.h>


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




- (instancetype)init;


-(NSString*)hashData:(NSData*)data;


///	NBSCryptoHash -hashString
///	@discussion		Hashing/checksum/digit/MAC a NSString in conjunction with the setted parameters
///	@param string		NSString to hashing/checksum/digit/MAC
///	@return			NSString as hexadecimal
-(NSString*)hashString:(NSString*)string;


///	NBSCryptoHash +hashString:(NSString*)string
///	@discussion		Hashing/checksum/digit/MAC of an NSString in conjunction with default parameters
///	@discussion		DEFAULT-PARAMETERS:
///					Algorithm		: NBSCrypto_HASH_SHA3_512
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@param string		NSString to Hashing/checksum/digit/MAC
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string;


///	NBSCryptoHash +hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm
///	@discussion		Hashing/checksum/digit/MAC of an NSString in conjunction with setted parameters
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@param string		NSString to Hashing/checksum/digit/MAC
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm;


///	NBSCryptoHash +hashStringWithCMAC:(NSString *)string andCipherAlgorithm:(NBSCrypto_MAC_CIPHER)cipherAlgorithm setKeyForMAC:(NSString *)macKey
///	@discussion		Hashing/checksum/digit/MAC of an NSString in conjunction with setted parameters using CMAC
///	@discussion		NBSCrypto_MAC_CIPHER is declared in NBSCryptoDefines.h
///	@param string		NSString to Hashing/checksum/digit/MAC
///	@param cipherAlgorithm	The NBSCrypto_MAC_CIPHER include the Bit-Length
///	@param macKey		The KEY for CMAC
///	@return			NSString as hexadecimal
+(NSString *)hashStringWithCMAC:(NSString *)string andCipherAlgorithm:(NBSCrypto_MAC_CIPHER)cipherAlgorithm setKeyForMAC:(NSString *)macKey;


///	NBSCryptoHash +hashStringWithHMAC:(NSString *)string withHashAlgorithm:(NBSCrypto_HASH)hashAlgorithm setKeyForMAC:(NSString *)macKey
///	@discussion		Hashing/checksum/digit/MAC of an NSString in conjunction with setted parameters using HMAC
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@param string		NSString to Hashing/checksum/digit/MAC
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@param macKey		The KEY for HMAC
///	@return			NSString as hexadecimal
+(NSString *)hashStringWithHMAC:(NSString *)string andHashAlgorithm:(NBSCrypto_HASH)hashAlgorithm setKeyForMAC:(NSString *)macKey;


///	NBSCryptoHash +hashStringWithKMAC:(NSString *)string withKMACAlgorithm:(NBSCrypto_KMAC)KMACAlgorithm setKeyForMAC:(NSString *)macKey setCustomizing:(NSString *)customizing setOutputLength:(unsigned long)outputLength
///	@discussion		Hashing/checksum/digit/MAC of an NSString in conjunction with setted parameters using KMAC
///	@discussion		NBSCrypto_KMAC is declared in NBSCryptoDefines.h
///	@param string		NSString to Hashing/checksum/digit/MAC
///	@param KMACAlgorithm	The NBSCrypto_KMAC include the Bit-Length
///	@param macKey		The KEY for KMAC
///	@param customizing	The CUSTOMIZING string for KMAC
///	@param outputLength	The OUTPUTLENGTH for KMAC
///	@return			NSString as hexadecimal
+(NSString *)hashStringWithKMAC:(NSString *)string andKMACAlgorithm:(NBSCrypto_KMAC)KMACAlgorithm setKeyForMAC:(NSString *)macKey setCustomizing:(NSString *)customizing setOutputLength:(unsigned long)outputLength;


///	NBSCryptoHash +hashStringWithOMAC:(NSString *)string andCipherAlgorithm:(NBSCrypto_MAC_CIPHER)cipherAlgorithm setKeyForMAC:(NSString *)macKey
///	@discussion		Hashing/checksum/digit/MAC of an NSString in conjunction with setted parameters using OMAC
///	@discussion		NBSCrypto_MAC_CIPHER is declared in NBSCryptoDefines.h
///	@param string		NSString to Hashing/checksum/digit/MAC
///	@param cipherAlgorithm	The NBSCrypto_MAC_CIPHER include the Bit-Length
///	@param macKey		The KEY for OMAC
///	@return			NSString as hexadecimal
+(NSString *)hashStringWithOMAC:(NSString *)string andCipherAlgorithm:(NBSCrypto_MAC_CIPHER)cipherAlgorithm setKeyForMAC:(NSString *)macKey;


///	NBSCryptoHash +hashStringWithPELICAN:(NSString * )string withHashAlgorithm:(NBSCrypto_HASH)hashAlgorithm setKeyForMAC:(NSString *)macKey
///	@discussion		Hashing/checksum/digit/MAC of an NSString in conjunction with setted parameters using PELICAN
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@param string		NSString to Hashing/checksum/digit/MAC
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@param macKey		The KEY for PELICAN
///	@return			NSString as hexadecimal
+(NSString *)hashStringWithPELICAN:(NSString * )string andHashAlgorithm:(NBSCrypto_HASH)hashAlgorithm setKeyForMAC:(NSString *)macKey;


///	NBSCryptoHash +hashStringWithPMAC:(NSString *)string andCipherAlgorithm:(NBSCrypto_MAC_CIPHER)cipherAlgorithm setKeyForMAC:(NSString *)macKey
///	@discussion		Hashing/checksum/digit/MAC of an NSString in conjunction with setted parameters using PMAC
///	@discussion		NBSCrypto_MAC_CIPHER is declared in NBSCryptoDefines.h
///	@param string		NSString to Hashing/checksum/digit/MAC
///	@param cipherAlgorithm	The NBSCrypto_MAC_CIPHER include the Bit-Length
///	@param macKey		The KEY for PMAC
///	@return			NSString as hexadecimal
+(NSString *)hashStringWithPMAC:(NSString *)string andCipherAlgorithm:(NBSCrypto_MAC_CIPHER)cipherAlgorithm setKeyForMAC:(NSString *)macKey;


///	NBSCryptoHash +hashStringWithPOLY1305:(NSString * )string withHashAlgorithm:(NBSCrypto_HASH)hashAlgorithm setKeyForMAC:(NSString *)macKey
///	@discussion		Hashing/checksum/digit/MAC of an NSString in conjunction with setted parameters using POLY1305
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@param string		NSString to Hashing/checksum/digit/MAC
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@param macKey		The KEY for POLY1305
///	@return			NSString as hexadecimal
+(NSString *)hashStringWithPOLY1305:(NSString *)string andHashAlgorithm:(NBSCrypto_HASH)hashAlgorithm setKeyForMAC:(NSString *)macKey;


//+(NSString *)hashStringWithF9:(NSString *)string andCipherAlgorithm:(NBSCrypto_MAC_CIPHER)cipherAlgorithm setKeyForMAC:(NSString *)macKey;


@end

NS_ASSUME_NONNULL_END
