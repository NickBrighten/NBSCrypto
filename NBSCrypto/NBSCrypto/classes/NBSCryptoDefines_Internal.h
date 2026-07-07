//
//	NBSCryptoDefines_Internal.h
//	NBSCrypto
//

#ifndef NBSCryptoDefines_Internal_h
#define NBSCryptoDefines_Internal_h


//IN BITS			//IN BYTES
#define _BIT_LENGTH_8		  1
#define _BIT_LENGTH_16		  2
#define _BIT_LENGTH_24		  3
#define _BIT_LENGTH_32		  4
#define _BIT_LENGTH_40		  5
#define _BIT_LENGTH_64		  8
#define _BIT_LENGTH_80		 10
#define _BIT_LENGTH_96		 12
#define _BIT_LENGTH_128		 16
#define _BIT_LENGTH_160 	 20
#define _BIT_LENGTH_192		 24
#define _BIT_LENGTH_224		 28
#define _BIT_LENGTH_256		 32
#define _BIT_LENGTH_288		 36
#define _BIT_LENGTH_320		 40
#define _BIT_LENGTH_352		 44
#define _BIT_LENGTH_384		 48
#define _BIT_LENGTH_416		 52
#define _BIT_LENGTH_448		 56
#define _BIT_LENGTH_480		 60
#define _BIT_LENGTH_512		 64
#define _BIT_LENGTH_576		 72
#define _BIT_LENGTH_768		 96
#define _BIT_LENGTH_1024	128
#define _BIT_LENGTH_1152	144
#define _BIT_LENGTH_2040	255
#define _BIT_LENGTH_2048	256


#define _HEX_PADDING @[@"\x00000000", @"\x00000001", @"\x00000002", @"\x00000003", @"\x00000004", @"\x00000005", @"\x00000006", @"\x00000007", @"\x00000008", @"\x00000009", @"\x0000000A", @"\x0000000B", @"\x0000000C", @"\x0000000D", @"\x0000000E", @"\x0000000F", @"\x00000010"]


#define _WARNING_BASE "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseConvert\nBase should be a value of NBSCrypto_BASE. For more informations see NBSCryptoBaseConvert.h and NBSCryptoDefines.h.\nBase has been set to the nearest value.\n"

#define _WARNING_Base16Encode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseEncode\nMode for Base16-Encode should be a value of NBSCrypto_BASE16MODE. For more informations see NBSCryptoBaseEncode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"

#define _WARNING_Base32Decode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseDecode\nMode for Base32-Decode should be a value of NBSCrypto_BASE32MODE. For more informations see NBSCryptoBaseDecode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"

#define _WARNING_Base32Encode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseEncode\nMode for Base32-Encode should be a value of NBSCrypto_BASE32MODE. For more informations see NBSCryptoBaseEncode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"

#define _WARNING_Base64Decode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseDecode\nMode for Base64-Decode should be a value of NBSCrypto_BASE64MODE. For more informations see NBSCryptoBaseDecode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"

#define _WARNING_Base64Encode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseEncode\nMode for Base64-Encode should be a value of NBSCrypto_BASE64MODE. For more informations see NBSCryptoBaseEncode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"


#endif
