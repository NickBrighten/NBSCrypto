//
//	NBSCryptoCrypt.h
//	NBSCrypto
//

#import <Foundation/Foundation.h>
#import <NBSCrypto/NBSCryptoDefines.h>


NS_ASSUME_NONNULL_BEGIN


///	NBSCryptoCrypt
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
@interface NBSCryptoCrypt : NSObject


///	INPUTFORMAT
///	@discussion		setINPUTFORMAT for decryption - Format for decrypted Input and TAG
///	@discussion		If no INPUTFORMAT is specified, NBSCryptoCrypt automatically set it to BASE64 (base64_decode).
///	@discussion		NBSCrypto_CIPHER_IO is declared in NBSCryptoDefines.h
@property (nonatomic, setter=setInputFormat:)		NBSCrypto_CIPHER_IO INPUTFORMAT;


///	OUTPUTFORMAT
///	@discussion		setOUTPUTFORMAT for encryption - Format for encrypted Output and TAG
///	@discussion		If no OUTPUTFORMAT is specified, NBSCryptoCrypt automatically set it to BASE64 (base64_encode).
///	@discussion		NBSCrypto_CIPHER_IO is declared in NBSCryptoDefines.h
@property (nonatomic, setter=setOutputFormat:)		NBSCrypto_CIPHER_IO OUTPUTFORMAT;


/// 	Cipher-Algorithm (NBSCrypto_CIPHER) inclusive Bit-Length and Mode
///	@discussion		Set a Cipher-Algorithm (NBSCrypto_CIPHER) for encryption and / or decryption
///	@discussion		The NBSCrypto_CIPHER include the Bit-Length and the Mode for encryption
///				and / or decryption
///	@discussion		NBSCrypto_CIPHER is declared in NBSCryptoDefines.h
@property (nonatomic, setter=setALGORITHM:)		NBSCrypto_CIPHER ALGORITHM;


///	KEY (Is strictly required)
///	@discussion		setKEY for encryption and / or decryption
///	@discussion		If no KEY is specified, NBSCryptoCrypt automatically pads the KEY with zeros
///				to the required length.
@property (nonatomic, setter=setKEY:)			NSString *KEY;


///	KEY2  (Recommended) - Required for F8-MODE and XTS-MODE
///	@discussion		setKEY2 for encryption and / or decryption
///	@discussion		KEY2 Is required for F8-MODE, LRW-MODE and XTS-MODE
///	@discussion		If no KEY2 is specified, NBSCryptoCrypt automatically pads KEY2 to the
///				required length with zeros, or truncates/pads KEY2 according to the
///				required length of the KEY2 from the input of the KEY.
///				In this case, KEY2 is padded with zeros, or is a subsequent substring
///				of the input of KEY (if the length does not match the required length of KEY2,
///				it will be padded with zeros).
@property (nonatomic, setter=setKEY2:)			NSString *KEY2;


///	IV (Initialization Vector)
///	@discussion		setIV (Initialization Vector) for encryption and / or decryption
///	@discussion		IV is not required for ECB-MODE
///	@discussion		In CCM-MODE, EAX-MODE, OCB-MODE, OCB3-MODE,
///				CHACHA8POLY1305, CHACHA12POLY1305 and CHACHA20POLY1305; IV = NONCE
///	@discussion		If no IV / NONCE is specified, NBSCryptoCrypt automatically pads
///				the IV / NONCE with zeros to the required length.
@property (nonatomic, setter=setIV:)			NSString *IV;


///	AAD / HEADER is required for
///				CCM-MODE, EAX-MODE, GCM-MODE, OCB3-MODE,
///				CHACHA8POLY1305, CHACHA12POLY1305 and CHACHA20POLY1305
///	@discussion		setAAD for encryption and / or decryption
///	@discussion		AAD / HEADER is required for CCM-MODE, EAX-MODE, GCM-MODE, OCB3-MODE
///				CHACHA8POLY1305, CHACHA12POLY1305 and CHACHA20POLY1305
///	@discussion		If no AAD / HEADER is specified, NBSCryptoCrypt automatically pads the
///				AAD / HEADER with zeros to the required length.
@property (nonatomic, setter=setAAD:)			NSString *AAD;


///	TAG is required for
///				CCM-Mode, EAX-MODE, GCM-MODE, OCB-MODE, OCB3-MODE,
///				CHACHA8POLY1305, CHACHA12POLY1305 and CHACHA20POLY1305
///	@discussion		setTAG or getTAG for encryption / decryption
///	@discussion		setTAG is required for decryption in
///				CCM-MODE, EAX-MODE, GCM-MODE, OCB-MODE, OCB3-MODE,
///				CHACHA8POLY1305, CHACHA12POLY1305 and CHACHA20POLY1305
///	@discussion		The getTAG command returns the required TAG for decryption in
///				CCM-MODE, EAX-MODE, GCM-MODE, OCB-MODE, OCB3-MODE,
///				CHACHA8POLY1305, CHACHA12POLY1305 and CHACHA20POLY1305 after encryption.
///				The TAG is generated automatically after encryption (getTAG)
///				and must be specified via setTAG for decryption.
///				The TAG have to be saved for decryption.
@property (nonatomic, setter=setTAG:, getter=getTAG)	NSString *TAG;




- (instancetype)init;


///	NBSCryptoCrypt - encryptString
///	@discussion		Encrypt an NSString to base64 encoded NSString
///	@param string		NSString to encrypt (returned NSString is base64 encoded)
- (NSString*)encryptString:(NSString*)string;


///	NBSCryptoCrypt - decryptString
///	@discussion		Decrypt an base64 encoded NSString
///	@param string		NSString to decrypt (given NSString must be a base64 encoded String)
- (NSString*)decryptString:(NSString*)string;


///	NBSCryptoCrypt - getIVLength
///	@discussion		Get the IV-Length (Initialization Vector Length) for the setted Cipher.
- (unsigned long)getIVLengthForCipher;


@end


NS_ASSUME_NONNULL_END
