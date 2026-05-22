# NBSCrypto
NBSCrypto is an ultra lightweight crytopgraphy framework for iOS, iPadOS, macOS, tvOS and watchOS.

The repository include the whole Xcode project with all targets, ready to build.\
NSCrypto is written in `Objective-C` and `C`.

It is possible to use the `.framework` or `.xcframework` in both Objective-C and Swift.\
To integrate the framework into an Objective-C project, you can use our guide: [Integrate NBSCrypto to an Objective-C Project](https://localhost) and to integrate it into a Swift project, you can use our guide: [Integrate NBSCrypto to an Swift Project](https://localhost).

Precompiled Builds will be soon available as single target `.framework` or as multiple tagets `.xcframework` for production/deployment and simulators.
#



# Table of Content
- [Collaboration](#collaboration)
- [Supported Cipher-Algorithms](#collaboration)
- [Supported Hash-Algorithms](#collaboration)
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
- __AES__
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
- __KASUMI__
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
#
