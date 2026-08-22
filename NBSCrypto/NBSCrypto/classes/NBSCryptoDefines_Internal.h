//
//	NBSCryptoDefines_Internal.h
//	NBSCrypto
//

#ifndef NBSCryptoDefines_Internal_h
#define NBSCryptoDefines_Internal_h


//IN BITS			//IN BYTES
#define _BIT_LENGTH_8		1
#define _BIT_LENGTH_16		_BIT_LENGTH_8 *   2
#define _BIT_LENGTH_24		_BIT_LENGTH_8 *   3
#define _BIT_LENGTH_32		_BIT_LENGTH_8 *   4
#define _BIT_LENGTH_40		_BIT_LENGTH_8 *   5
#define _BIT_LENGTH_48		_BIT_LENGTH_8 *   6
#define _BIT_LENGTH_56		_BIT_LENGTH_8 *   7
#define _BIT_LENGTH_64		_BIT_LENGTH_8 *   8
#define _BIT_LENGTH_72		_BIT_LENGTH_8 *   9
#define _BIT_LENGTH_80		_BIT_LENGTH_8 *  10
#define _BIT_LENGTH_88		_BIT_LENGTH_8 *  11
#define _BIT_LENGTH_96	 	_BIT_LENGTH_8 *  12
#define _BIT_LENGTH_128		_BIT_LENGTH_8 *  16
#define _BIT_LENGTH_160 	_BIT_LENGTH_8 *  20
#define _BIT_LENGTH_192		_BIT_LENGTH_8 *  24
#define _BIT_LENGTH_224		_BIT_LENGTH_8 *  28
#define _BIT_LENGTH_256		_BIT_LENGTH_8 *  32
#define _BIT_LENGTH_288		_BIT_LENGTH_8 *  36
#define _BIT_LENGTH_320		_BIT_LENGTH_8 *  40
#define _BIT_LENGTH_352		_BIT_LENGTH_8 *  44
#define _BIT_LENGTH_384		_BIT_LENGTH_8 *  48
#define _BIT_LENGTH_416		_BIT_LENGTH_8 *  52
#define _BIT_LENGTH_448		_BIT_LENGTH_8 *  56
#define _BIT_LENGTH_480		_BIT_LENGTH_8 *  60
#define _BIT_LENGTH_512		_BIT_LENGTH_8 *  64
#define _BIT_LENGTH_576		_BIT_LENGTH_8 *  72
#define _BIT_LENGTH_640		_BIT_LENGTH_8 *  80
#define _BIT_LENGTH_704		_BIT_LENGTH_8 *  88
#define _BIT_LENGTH_768		_BIT_LENGTH_8 *  96
#define _BIT_LENGTH_832		_BIT_LENGTH_8 * 104
#define _BIT_LENGTH_896		_BIT_LENGTH_8 * 112
#define _BIT_LENGTH_1008	_BIT_LENGTH_8 * 126
#define _BIT_LENGTH_1016	_BIT_LENGTH_8 * 127
#define _BIT_LENGTH_1024	_BIT_LENGTH_8 * 128
#define _BIT_LENGTH_1152	_BIT_LENGTH_8 * 144
#define _BIT_LENGTH_2040	_BIT_LENGTH_8 * 255
#define _BIT_LENGTH_2048	_BIT_LENGTH_8 * 256
#define _BIT_LENGTH_4096	_BIT_LENGTH_8 * 512


#define _HEX_PADDING @[@"\x00000000", @"\x00000001", @"\x00000002", @"\x00000003", @"\x00000004", @"\x00000005", @"\x00000006", @"\x00000007", @"\x00000008", @"\x00000009", @"\x0000000A", @"\x0000000B", @"\x0000000C", @"\x0000000D", @"\x0000000E", @"\x0000000F", @"\x00000010"]


#define _WARNING_BASE "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseConvert\nBase should be a value of NBSCrypto_BASE. For more informations see NBSCryptoBaseConvert.h and NBSCryptoDefines.h.\nBase has been set to the nearest value.\n"

#define _WARNING_Base16Encode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseEncode\nMode for Base16-Encode should be a value of NBSCrypto_BASE16MODE. For more informations see NBSCryptoBaseEncode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"

#define _WARNING_Base32Decode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseDecode\nMode for Base32-Decode should be a value of NBSCrypto_BASE32MODE. For more informations see NBSCryptoBaseDecode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"

#define _WARNING_Base32Encode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseEncode\nMode for Base32-Encode should be a value of NBSCrypto_BASE32MODE. For more informations see NBSCryptoBaseEncode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"

#define _WARNING_Base64Decode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseDecode\nMode for Base64-Decode should be a value of NBSCrypto_BASE64MODE. For more informations see NBSCryptoBaseDecode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"

#define _WARNING_Base64Encode "--- WARNING ---\nNBSCrypto -> NBSCryptoBaseEncode\nMode for Base64-Encode should be a value of NBSCrypto_BASE64MODE. For more informations see NBSCryptoBaseEncode.h and NBSCryptoDefines.h.\nMode has been set to the nearest value.\n"


#endif
