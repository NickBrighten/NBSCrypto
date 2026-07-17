//
//	nbs_crypto.h
//

#ifndef nbs_crypto_h
#define nbs_crypto_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

#ifdef __cplusplus
    extern "C" {
#endif
    #include "nbs_bases.h"
    #include "nbs_ciphers.h"
    #include "nbs_hashes.h"
    #include "nbs_mac.h"
    #include "nbs_misc.h"
    #include "nbs_modes.h"
#ifdef __cplusplus
    }
#endif

#define NBS_CRYPTO_VERSION	"1.0.0"
#define NBS_CRYPTO_BUILDNUMBER	"260717"

#endif /* nbs_crypto_h */
