# NBSCrypto
NBSCrypto is an ultra lightweight crytopgraphy framework for iOS, iPadOS, macOS, tvOS and watchOS.

This repository include the whole Xcode project with all targets, ready to build.\
NSCrypto is written in `Objective-C` and `C`.

It is possible to use the `.framework` or `.xcframework` in both Objective-C and Swift.\
To integrate the `.framework` or `.xcframework` into an Objective-C project, you can use our guide: [Integrate NBSCrypto to an Objective-C Project](https://localhost) and to integrate it into a Swift project, you can use our guide: [Integrate NBSCrypto to an Swift Project](https://localhost).

Precompiled Builds will be available as multiple tagets `.xcframework` for production/deployment [here](https://github.com/NickBrighten/NBSCrypto/releases).

An XCFramework `.xcframework` is Apple's recommended, modern format for distributing compiled binary code and frameworks. It allows developers to bundle libraries supporting multiple platforms, such as iOS, iPadOS, macOS, tvOS, visionOS and watchOS, into a single, unified package that works on both physical devices and simulators.

If you wish to use this source code for your own library (and for platforms other than Apple devices), you can start with the `src` folder and extend and optimize the code.
#



# Table of Content
- [Collaboration](#collaboration)
- [Supported Cipher-Algorithms](#supported-cipher-algorithms)
- [Supported Hash-Algorithms](#supported-hash-algorithms)
#



# Collaboration
Feel free and collaborate with us and others to bring up this repository.\
Please keep in mind a few important things to ensure smooth collaboration.

## Branches
>[!CAUTION]
>Please be aware, that all branches besides `main` can and will be force-pushed, rebased and/or removed!

If you want to rely on such an unstable branch, create your own fork of this repository to make sure nothing breaks for you.

## Submitting Patches & Reviews
>[!IMPORTANT]
>Please branch off from `dev` if you want to submit a patch.\
>Patch integration will be faster if tests and documentation are included.

We're using Pull Request reviews to make sure that the code is in line with the existing code base.\
Please have a look [here](https://help.github.com/articles/approving-a-pull-request-with-required-reviews/) to get an idea of the approach.
#



# Supported Cipher-Algorithms
- __AES / RIJNDAEL__
    - BIT-LENGTH: `128` `192` `256`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __ANUBIS / ANUBIS-TWEAK__
    - BIT-LENGTH: `128` `160` `192` `224` `256` `288` `320`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __ARIA__
    - BIT-LENGTH: `128` `192` `256`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __BLOWFISH__
    - BIT-LENGTH: `128` up to `576`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __CAMELLIA__
    - BIT-LENGTH: `128` `192` `256`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __CAST-5__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __CAST-6__
    - BIT-LENGTH: `128` `160` `192` `224` `256`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __CHACHA8__
    - BIT-LENGTH: `128` `256`
    - MODES: `CHACHA8POLY1305`
- __CHACHA12__
    - BIT-LENGTH: `128` `256`
    - MODES: `CHACHA12POLY1305`
- __CHACHA20__
    - BIT-LENGTH: `128` `256`
    - MODES: `CHACHA20POLY1305`
- __DES__
    - BIT-LENGTH: `64`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __DES-EDE / DES-EDE2__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __DES3 / DES-EDE3__
    - BIT-LENGTH: `192`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __IDEA__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __KASUMI / A5-3__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __KHAZAD__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __LEA__
    - BIT-LENGTH: `128` `192` `256`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __MARS__
    - BIT-LENGTH: `128` `160` `192` `224` `256` `288` `320` `352` `384` `416` `448`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __NOEKEON__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __PRESENT__
    - BIT-LENGTH: `80` `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __RC2__
    - BIT-LENGTH: `1024`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __RC4__
    - BIT-LENGTH: `2048`
    - MODES: `none`
- __RC6__
    - BIT-LENGTH: `256`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __SAFER-K64 / SAFER-SK64__
    - BIT-LENGTH: `64`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __SAFER-K128 / SAFER-SK128__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __SAFER+__
    - BIT-LENGTH: `128` `192` `256`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __SEED__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __SERPENT__
    - BIT-LENGTH: `128` `192` `256`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __SKIPJACK__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __SM4__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __TEA__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
- __TWOFISH__
    - BIT-LENGTH: `128` `192` `256`
    - MODES: `CBC` `CCM` `CFB` `CTR` `EAX` `ECB` `F8` `GCM` `LRW` `OCB` `OCB3` `OFB` `XTS`
- __XTEA__
    - BIT-LENGTH: `128`
    - MODES: `CBC` `CFB` `CTR` `EAX` `ECB` `F8` `OCB` `OFB`
#



# Supported Hash-Algorithms
- __ADLER32__
    - BIT-LENGTH: `32`
- __ARIRANG__
    - BIT-LENGTH: `224` `256` `384` `512`
- __BLAKE2B__
    - BIT-LENGTH: `160` `256` `384` `512`
- __BLAKE2S__
    - BIT-LENGTH: `128` `160` `224` `256`
- __BLAKE3__
    - BIT-LENGTH: `256`
- __BLUEMIDNIGHTWISH__
    - BIT-LENGTH: `224` `256` `384` `512`
- __CHI__
    - BIT-LENGTH: `224` `256` `384` `512`
- __CRC-8__
    - BIT-LENGTH: `8`
    - VARIATIONS: `AES` `AUTOSAR` `BLUETOOTH` `CCITT` `CDMA2000` `DARC` `DVB-S2` `EBU` `GSM-A` `GSM-B` `HITAG` `I-432-1` `ICODE` `ITU` `LTE` `MAXIM` `MAXIM-DOWN` `MIFARE-MAD` `NRSC-5` `OPENSEAFTY` `ROHC` `SAE-J1850` `SMBUS` `TECH-3250` `WCDMA`
- __CRC-16__
    - BIT-LENGTH: `16`
    - VARIATIONS: `ACORN` `ARC` `AUG-CCITT` `AUTOSAR` `BLUETOOTH` `BUYPASS` `CCITT` `CCITT-FALSE` `CCITT-TRUE` `CDMA2000` `CMS` `DARC` `DDS110` `DECT-R` `DECT-X` `DNP` `EN-13757` `EPC` `EPC-C1G2` `GENIBUS` `GSM` `IBM` `IBM-3740` `IBM-SDLC` `ICODE` `IEC-61158-2` `ISO-HDLC` `ISO-IEC-14443-3-A` `ISO-IEC-14443-3-B` `KERMIT` `LHA` `LJ1200` `LTE` `M17` `MAXIM` `MAXIM-DOWN` `MCRF4XX` `MODBUS` `NRSC-5` `OPENSEAFTY-A` `OPENSEAFTY-B` `PROFIBUS` `RIELLO` `SPI-FUJITSU` `T10-DIF` `TELEDISK` `TMS37157` `UMTS` `USB` `V41LSB` `V41MSB` `VERIFONE` `X-25` `XMODEM` `ZMODEM`
- __CRC-24__
    - BIT-LENGTH: `24`
    - VARIATIONS: `BLE` `FLEXRAY-A` `FLEXRAY-B` `INTERLAKEN` `LTE-A` `LTE-B` `OPENPGP` `OS-9` `RADIX-64` `RTCM-104V3` `WDCMA`
- __CRC-32__
    - BIT-LENGTH: `32`
    - VARIATIONS: `AAL5` `ADCCP` `AIXM` `AUTOSAR` `B` `BASE91-C` `BASE91-D` `BZIP2` `C` `CASTAGNOLI` `CD-ROM-EDC` `CKSUM` `D` `DECT-B` `IEEE-802-3` `INTERLAKEN` `ISCSI` `ISO-HDLC` `JAMCRC` `MEF` `MPEG2` `NVME` `POSIX` `Q` `V42` `XFER` `XZ`
- __CRC-64__
    - BIT-LENGTH: `64`
    - VARIATIONS: `ECMA-182` `GO-ECMA` `GO-ISO` `ISO-3309` `MS` `NVME` `REDIS` `WE` `XZ`
- __ECHO__
    - BIT-LENGTH: `224` `256` `384` `512`
- __FNV1-32 / FNV1a-32__
    - BIT-LENGTH: `32`
- __FNV1-64 / FNV1a-64__
    - BIT-LENGTH: `64`
- __GOST / GOST-CRYPTO__
    - BIT-LENGTH: `256`
- __GROESTL__
    - BIT-LENGTH: `224` `256` `384` `512`
- __HAMSI__
    - BIT-LENGTH: `224` `256` `384` `512`
- __HAVAL-3 / HAVAL-4 / HAVAL-5__
    - BIT-LENGTH: `128` `160` `192` `224` `256`
- __JH__
    - BIT-LENGTH: `224` `256` `384` `512`
- __JOAAT__
    - BIT-LENGTH: `32`
- __KECCAK__
    - BIT-LENGTH: `224` `256` `384` `512`
- __KUPYNA__
    - BIT-LENGTH: `256` `512`
- __LANE__
    - BIT-LENGTH: `224` `256` `384` `512`
- __LESAMNTA__
    - BIT-LENGTH: `224` `256` `384` `512`
- __LUFFA__
    - BIT-LENGTH: `224` `256` `384` `512`
- __MD2 / MD4 / MD5__
    - BIT-LENGTH: `128`
- __MURMUR3A__
    - BIT-LENGTH: `32`
- __MURMUR3C / MURMUR3F__
    - BIT-LENGTH: `128`
- __RIPEMD__
    - BIT-LENGTH: `128` `160` `256` `320`
- __SHA-1__
    - BIT-LENGTH: `160`
- __SHA-2__
    - BIT-LENGTH: `224` `256` `384` `512`
- __SHA-3__
    - BIT-LENGTH: `224` `256` `384` `512`
- __SHABAL__
    - BIT-LENGTH: `192` `224` `256` `384` `512`
- __SHAKE__
    - BIT-LENGTH: `128` `256`
- __SHAVITE3__
    - BIT-LENGTH: `224` `256` `384` `512`
- __SIMD__
    - BIT-LENGTH: `224` `256` `384` `512`
- __SM3__
    - BIT-LENGTH: `256`
- __SNEFRU__
    - BIT-LENGTH: `256`
- __STREEBOG / GOST-R34112012__
    - BIT-LENGTH: `256` `512`
- __SWIFFTX__
    - BIT-LENGTH: `224` `256` `384` `512`
- __TIGER / TIGER-2__
    - BIT-LENGTH: `128` `160` `192`
- __WHIRPOOL__
    - BIT-LENGTH: `512`
- __XXH__
    - BIT-LENGTH: `32` `64` `128`
#
