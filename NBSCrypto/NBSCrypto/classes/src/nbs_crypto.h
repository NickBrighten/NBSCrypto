//
//	nbs_crypto.h
//

#ifndef nbs_crypto_h
#define nbs_crypto_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <math.h>


#ifdef __cplusplus
    extern "C" {
#endif
    #include "nbs_bases.h"
    #include "nbs_ciphers.h"
    #include "nbs_hashes.h"
    #include "nbs_kdf.h"
    #include "nbs_mac.h"
    #include "nbs_misc.h"
    #include "nbs_modes.h"
#ifdef __cplusplus
    }
#endif

#define NBSCRYPTO_VERSION	"1.0.0"
#define NBSCRYPTO_BUILDNUMBER	"261127"
#define NBSCRYPTO_COPYRIGHT	"© 2026. Nick Brighten, NB-Systems."

#endif /* nbs_crypto_h */
