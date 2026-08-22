//
//	siv.c
//	Authors / Developers		: Phillip Rogaway, Thomas Shrimpton, D. Harkins
//	Last Modified (Original)	: 2006
//

#include "nbs_crypto.h"
#include <stdarg.h>




#pragma mark - DEFINES
#if defined(__GNUC__)
    #define NBS_ALIGN_MSVC(n)
    #define NBS_ALIGN(n) __attribute__((aligned(n)))
#elif defined(_MSC_VER)
    #define NBS_ALIGN_MSVC(n) __declspec(align(n))
    #define NBS_ALIGN(n)
#else
    #define NBS_ALIGN_MSVC(n)
    #define NBS_ALIGN(n)
#endif

#define NBS_STATIC_ASSERT(msg, cond) typedef char nbs_static_assert_##msg[(cond) ? 1 : -1];
#define NBS_ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
#define NBS_NULL ((void *)0)

static const unsigned long _siv_max_aad_components = 126;

NBS_ALIGN_MSVC(16)
typedef struct siv_buf_t {
    union {
	unsigned char byte[16];
    } u;
} siv_buf_t NBS_ALIGN(16);

typedef struct siv_omac_ctx_t {
    omac_state omac;
    int cipher;
} siv_omac_ctx_t;

typedef struct {
    siv_buf_t Q, V;
} siv_state;

NBS_STATIC_ASSERT(size_of_siv_buf_t_is_16_bytes, sizeof(siv_buf_t) == 16);




#pragma mark - INLINE
static inline int _siv_ctx_init(int cipher, const unsigned char *key, unsigned long keylen, siv_omac_ctx_t *ctx)
{
    ctx->cipher = cipher;
    return omac_init(cipher, key, keylen, &ctx->omac);
}

static inline int _siv_omac_memory(siv_omac_ctx_t *ctx, const unsigned char *in, unsigned long inlen, siv_buf_t *out)
{
    int err;
    unsigned long len = sizeof(*out);
    omac_state omac = ctx->omac;
    if ((err = omac_process(in, inlen, &omac)) != NBSCrypto_OK) {
	return err;
    }
    err = omac_done(out->u.byte, &len, &omac);
    zeromem(&omac, sizeof(omac));
    return err;
}

static inline int _siv_omac_vprocess_i(omac_state *omac, const unsigned char *in, unsigned long inlen, va_list args)
{
    const unsigned char * curptr = in;
    unsigned long curlen = inlen;
    int err;
    for (;;) {
	if ((err = omac_process(curptr, curlen, omac)) != NBSCrypto_OK) {
	    return err;
	}
	curptr = va_arg(args, const unsigned char*);
	if (curptr == NULL) {
	    break;
	}
	curlen = va_arg(args, unsigned long);
    }
    return NBSCrypto_OK;
}

static inline int _siv_omac_vprocess(omac_state *omac, const unsigned char *in, unsigned long inlen, va_list args)
{
    return _siv_omac_vprocess_i(omac, in, inlen, args);
}

static inline int _siv_omac_memory_multi(siv_omac_ctx_t *ctx, siv_buf_t *out, const unsigned char *in, unsigned long inlen, ...)
{
    int err;
    va_list args;
    unsigned long len = sizeof(*out);
    omac_state omac = ctx->omac;
    va_start(args, inlen);

    if ((err = _siv_omac_vprocess(&omac, in, inlen, args)) != NBSCrypto_OK) {
	return err;
    }
    err = omac_done(out->u.byte, &len, &omac);
    zeromem(&omac, sizeof(omac));
    return err;
}

static inline void _siv_dbl(siv_buf_t *D_)
{
    unsigned char *D = D_->u.byte;
    unsigned int y, mask, msb, len;

    mask = 0x87;
    len = 16;

    msb = D[0] >> 7;

    for (y = 0; y < (len - 1); y++) {
	D[y] = ((D[y] << 1) | (D[y + 1] >> 7)) & 255;
    }
    D[len - 1] = ((D[len - 1] << 1) ^ (msb ? mask : 0)) & 255;
}

static inline void _siv_xor_buf(const siv_buf_t *a, siv_buf_t *b)
{
    unsigned int n;

    for (n = 0; n < NBS_ARRAY_SIZE(a->u.byte); ++n) {
	b->u.byte[n] ^= a->u.byte[n];
    }
}

static inline int _siv_S2V_zero(siv_omac_ctx_t *ctx, siv_buf_t *D)
{
    const siv_buf_t zero = {0};
    return _siv_omac_memory(ctx, zero.u.byte, sizeof(zero), D);
}

static inline int _siv_S2V_dbl_xor_omac(siv_omac_ctx_t *ctx, const unsigned char *aad, unsigned long aadlen, siv_buf_t *D)
{
    int err;
    siv_buf_t TMP;
    if ((err = _siv_omac_memory(ctx, aad, aadlen, &TMP)) != NBSCrypto_OK) {
	return err;
    }
    _siv_dbl(D);
    _siv_xor_buf(&TMP, D);
    return err;
}

static inline int _siv_S2V_T(siv_omac_ctx_t *ctx, const unsigned char *in, unsigned long inlen, siv_buf_t *D, siv_buf_t *V)
{
    siv_buf_t T;
    int err;

    if (inlen >= 16) {
	memcpy(&T, &in[inlen - 16], 16);
	_siv_xor_buf(D, &T);
	err = _siv_omac_memory_multi(ctx, V, in, inlen - 16, &T, sizeof(T), NBS_NULL);
    } else {
	_siv_dbl(D);
	memset(&T, 0, sizeof(T));
	if (inlen != 0) memcpy(&T, in, inlen);
	T.u.byte[inlen] = 0x80;
	_siv_xor_buf(D, &T);

	err = _siv_omac_memory(ctx, T.u.byte, sizeof(T), V);
    }
    return err;
}

static inline int _siv_S2V(int cipher, const unsigned char *key, unsigned long keylen, unsigned long adnum, const unsigned char *ad, unsigned long adlen, const unsigned char *in, unsigned long inlen, siv_buf_t *V)
{
    int err;
    siv_buf_t D;
    unsigned long n = 0;
    siv_omac_ctx_t ctx;

    if ((err = _siv_ctx_init(cipher, key, keylen, &ctx)) != NBSCrypto_OK) {
	return err;
    }

    if ((err = _siv_S2V_zero(&ctx, &D)) != NBSCrypto_OK) {
	return err;
    }

    while (n < adnum) {
	if (n >= _siv_max_aad_components) {
	    return NBSCrypto_ERROR;
	}
	if ((err = _siv_S2V_dbl_xor_omac(&ctx, ad, adlen, &D)) != NBSCrypto_OK) {
	    return err;
	}

	n++;
    }

    return _siv_S2V_T(&ctx, in, inlen, &D, V);
}

static inline void _siv_bitand(const void* V, siv_buf_t* Q)
{
    memcpy(Q, V, sizeof(*Q));
    Q->u.byte[8] &= 0x7F;
    Q->u.byte[12] &= 0x7F;
}

static inline int _siv_ctr_crypt_memory(int cipher, const unsigned char *IV, const unsigned char *key, int keylen, const unsigned char *in, unsigned char *out, unsigned long len)
{
    int err;
    cm_CTR ctr;

    if ((err = ctr_start(cipher, IV, key, keylen, 0, CTR_COUNTER_BIG_ENDIAN | 16, &ctr)) != NBSCrypto_OK) {
	goto out;
    }
    if ((err = ctr_encrypt(in, out, len, &ctr)) != NBSCrypto_OK) {
	goto out;
    }
    if ((err = ctr_done(&ctr)) != NBSCrypto_OK) {
	goto out;
    }

out:
    return err;
}




#pragma mark - FUNCTIONS
int siv_encrypt_memory(int cipher, const unsigned char *key, unsigned long keylen, unsigned long addnum, const unsigned char *add, unsigned long addlen, const unsigned char *pt, unsigned long ptlen, unsigned char *ct, unsigned long *ctlen)
{
    int err;
    const unsigned char *K1, *K2;
    void *work = NULL;
    siv_state siv;

    if (ptlen + 16 < ptlen) {
	return NBSCrypto_ERROR;
    }

    if (*ctlen < ptlen + 16) {
	*ctlen = ptlen + 16;
	return NBSCrypto_ERROR;
    }

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    work = malloc(ptlen + 16);
    if (work == NULL) {
	return NBSCrypto_ERROR;
    }

    K1 = key;
    K2 = &key[keylen/2];

    if ((err = _siv_S2V(cipher, K1, keylen/2, addnum, add, addlen, pt, ptlen, &siv.V)) != NBSCrypto_OK) {
	goto out;
    }

    _siv_bitand(&siv.V, &siv.Q);

    if ((err = _siv_ctr_crypt_memory(cipher, siv.Q.u.byte, K2, (int)(keylen/2), pt, work, ptlen)) != NBSCrypto_OK) {
	goto out;
    }
    memcpy(ct, &siv.V, 16);
    memcpy(ct + 16, work, ptlen);
    *ctlen = ptlen + 16;

out:
    zeromem(work, ptlen + 16);
    free(work);

    return err;
}

int siv_decrypt_memory(int cipher, const unsigned char *key, unsigned long keylen, unsigned long aadnum, const unsigned char *aad, unsigned long aadlen, const unsigned char *ct, unsigned long ctlen, unsigned char *pt, unsigned long *ptlen)
{
    int err;
    unsigned char *pt_work;
    const unsigned char *K1, *K2, *ct_work;
    siv_state siv;

    if (ctlen < 16) {
	return NBSCrypto_ERROR;
    }

    if (*ptlen < (ctlen - 16)) {
	*ptlen = ctlen - 16;
	return NBSCrypto_ERROR;
    }

    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }

    *ptlen = ctlen - 16;
    pt_work = malloc(*ptlen);
    if (pt_work == NULL) {
	return NBSCrypto_ERROR;
    }

    K1 = key;
    K2 = &key[keylen/2];

    ct_work = ct;
    _siv_bitand(ct_work, &siv.Q);
    ct_work += 16;

    if ((err = _siv_ctr_crypt_memory(cipher, siv.Q.u.byte, K2, (int)(keylen/2), ct_work, pt_work, *ptlen)) != NBSCrypto_OK) {
	goto out;
    }

    if ((err = _siv_S2V(cipher, K1, keylen/2, aadnum, aad, aadlen, pt_work, *ptlen, &siv.V)) != NBSCrypto_OK) {
	goto out;
    }

    err = mem_neq(&siv.V, ct, sizeof(siv.V));
    copy_or_zeromem(pt_work, pt, *ptlen, err);
out:
    zeromem(pt_work, *ptlen);
    free(pt_work);

    return err;
}
