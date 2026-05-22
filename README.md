# NBSCrypto
NBSCrypto is an ultra lightweight crytopgraphy framework for iOS, iPadOS, macOS, tvOS and watchOS.

Builds will be soon available as single target `.framework` or as multiple tagets `.xcframework` for production/deployment and simulator.

NSCrypto is written in `Objective-C` and `C`.
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
#



# Supported Hash-Algorithms
#
