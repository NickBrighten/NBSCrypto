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


/// 	HASH-Algorithm (NBSCrypto_HASH) inclusive Bit-Length
///	@discussion		Set a HASH-Algorithm (NBSCrypto_HASH) for hashing/checksum/digit/MAC
///	@discussion		The NBSCrypto_HASH include the Bit-Length
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
@property (nonatomic, setter=setAlgorithm:)		NBSCrypto_HASH ALGORITHM;


///	Using MAC
///	@discussion		useMAC set a MAC-Algorithm (NBSCrypto_MAC) for hashing/checksum/digit/MAC
///	@discussion		A KEY is required for security reason
///	@discussion		If no KEY is specified, NBSCrypto automatically pads the KEY with zeros
///				to the required length.
@property (nonatomic, setter=useMAC:)			NBSCrypto_MAC MAC;


///	MACKEY (Required for MAC)
///	@discussion		setKeyForMAC for hashing/checksum/digit/MAC
///	@discussion		If no KEY is specified, NBSCrypto automatically pads the KEY with zeros
///				to the required length.
@property (nonatomic, setter=setKeyForMAC:)		NSString *MACKEY;


///	CUSTOMIZING (Optional for KMAC)
///	@discussion		setKeyForMAC for hashing/checksum/digit/MAC
///	@discussion		If no KEY is specified, NBSCrypto automatically pads the KEY with zeros
///				to the required length.
@property (nonatomic, setter=setCustomizing:)		NSString *CUSTOMIZING;


///	outputLengthMAC (Optional for KMAC)
///	@discussion		setOutputLengthMAC for hashing/checksum/digit/MAC
///	@discussion		If no outputLengthMAC is specified, NBSCrypto automatically set it to DEFAULT.
@property (nonatomic, setter=setOutputLengthMAC:)	unsigned long OUTPUTLENGTHMAC;


- (instancetype)init;


-(NSString*)hashData:(NSData*)data;


///	NBSCryptoHash -hashString
///	@discussion		Hashing/checksum/digit/MAC a NSString in conjunction with the setted parameters
///	@param string		NSString to hashing/checksum/digit/MAC
///	@return			NSString as hexadecimal
-(NSString*)hashString:(NSString*)string;


///	NBSCryptoHash +hashString:(NSString*)string
///	@discussion		Hashing/checksum/digit of an NSString in conjunction with default parameters
///	@discussion		DEFAULT-PARAMETERS:
///					Algorithm		: NBSCrypto_HASH_SHA3_512
///					useMAC		: NBSCrypto_MAC_NONE
///					setKeyForHMAC	: NULL
///					setOutputLengthMAC	: NULL
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@param string		NSString to hashing/checksum/digit
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string;


///	NBSCryptoHash +hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm
///	@discussion		Hashing/checksum/digit of an NSString in conjunction with setted  parameters
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@param string		NSString to hashing/checksum/digit
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm;


///	NBSCryptoHash +hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm useMAC:(NBSCrypto_MAC)useMAC setKeyForMAC:(NSString*)macKey
///	@discussion		Hashing/checksum/digit/HMAC a NSString in conjunction with the setted parameters
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@discussion		If no KEY is specified, NBSCryptoHash automatically pads the KEY with zeros
///				to the required length or use no KEY in conjunction to the used MAC-Algorithm (like KMAC)
///	@param string		NSString to hashing/checksum/digit/MAC
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@param useMAC		The NBSCrypto_MAC which is used
///	@param macKey		Set the KEY for MAC
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm useMAC:(NBSCrypto_MAC)useMAC setKeyForMAC:(NSString*)macKey;


///	NBSCryptoHash +hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm useMAC:(NBSCrypto_MAC)useMAC setKeyForMAC:(NSString*)macKey setOutputLengthForMAC:(unsigned long)outputLengthMAC
///	@discussion		Hashing/checksum/digit/HMAC a NSString in conjunction with the setted parameters
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@discussion		If no KEY is specified, NBSCryptoHash automatically pads the KEY with zeros
///				to the required length or use no KEY in conjunction to the used MAC-Algorithm (like KMAC)
///	@param string		NSString to hashing/checksum/digit/MAC
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@param useMAC		The NBSCrypto_MAC which is used
///	@param macKey		Set the KEY for MAC
///	@param outputLengthMAC	Set the given length of the output (in BIT) of a MAC-Algorithm (only required for KMAC)
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm useMAC:(NBSCrypto_MAC)useMAC setKeyForMAC:(NSString*)macKey setOutputLengthForMAC:(unsigned long)outputLengthMAC;


///	NBSCryptoHash +hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm useMAC:(NBSCrypto_MAC)useMAC setKeyForMAC:(NSString*)macKey setCustomizing:(NSString*)customizing setOutputLengthForMAC:(unsigned long)outputLengthMAC
///	@discussion		Hashing/checksum/digit/HMAC a NSString in conjunction with the setted parameters
///	@discussion		NBSCrypto_HASH is declared in NBSCryptoDefines.h
///	@discussion		If no KEY is specified, NBSCryptoHash automatically pads the KEY with zeros
///				to the required length or use no KEY in conjunction to the used MAC-Algorithm (like KMAC)
///	@param string		NSString to hashing/checksum/digit/MAC
///	@param hashAlgorithm	The NBSCrypto_HASH include the Bit-Length
///	@param useMAC		The NBSCrypto_MAC which is used
///	@param macKey		Set the KEY for MAC
///	@param customizing	Set the COSTUMIZING for KMAC
///	@param outputLengthMAC	Set the given length of the output (in BIT) of a MAC-Algorithm (only required for KMAC)
///	@return			NSString as hexadecimal
+(NSString*)hashString:(NSString*)string withAlgorithm:(NBSCrypto_HASH)hashAlgorithm useMAC:(NBSCrypto_MAC)useMAC setKeyForMAC:(NSString*)macKey setCustomizing:(NSString*)customizing setOutputLengthForMAC:(unsigned long)outputLengthMAC;

@end

NS_ASSUME_NONNULL_END
