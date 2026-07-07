//
//	ocb3.c
//	Authors / Developers		: Phillip Rogaway, Ted Krovetz
//	Last Modified (Original)	: 2011
//

#include "nbs_crypto.h"




#pragma mark - DEFINES
static const struct {
    int len;
    unsigned char poly_mul[MAXBLOCKSIZE];
} polys[] = {
    {
	8,
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B }
    }, {
	16,
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 }
    }
};




#pragma mark - INLINE
static inline void _ocb3_int_calc_offset_zero(cm_OCB3 *ocb, const unsigned char *nonce, unsigned long noncelen, unsigned long taglen)
{
    int x, y, bottom;
    int idx, shift;
    unsigned char iNonce[MAXBLOCKSIZE];
    unsigned char iKtop[MAXBLOCKSIZE];
    unsigned char iStretch[MAXBLOCKSIZE+8];

    zeromem(iNonce, sizeof(iNonce));
    for (x = ocb->block_len-1, y=0; y<(int)noncelen; x--, y++) {
	iNonce[x] = nonce[noncelen-y-1];
    }

    iNonce[x] = 0x01;
    iNonce[0] |= ((taglen*8) % 128) << 1;
    bottom = iNonce[ocb->block_len-1] & 0x3F;
    iNonce[ocb->block_len-1] = iNonce[ocb->block_len-1] & 0xC0;

    if ((cipher_descriptor[ocb->cipher].encrypt(iNonce, iKtop, &ocb->cs)) != NBSCrypto_OK) {
	zeromem(ocb->Offset_current, ocb->block_len);
	return;
    }

    for (x = 0; x < ocb->block_len; x++) {
	iStretch[x] = iKtop[x];
    }

    for (y = 0; y < 8; y++) {
	iStretch[x+y] = iKtop[y] ^ iKtop[y+1];
    }

    idx = bottom / 8;
    shift = (bottom % 8);

    for (x = 0; x < ocb->block_len; x++) {
	ocb->Offset_current[x] = iStretch[idx+x] << shift;
	if (shift > 0) {
	    ocb->Offset_current[x] |= iStretch[idx+x+1] >> (8-shift);
	}
    }
}

static inline int _ocb3_int_ntz(unsigned long x)
{
    int c;
    x &= 0xFFFFFFFFUL;
    c = 0;
    while ((x & 1) == 0) {
	++c;
	x >>= 1;
    }
    return c;
}

static inline void _ocb3_int_xor_blocks(unsigned char *out, const unsigned char *block_a, const unsigned char *block_b, unsigned long block_len)
{
    int x;
    if (out == block_a) {
	for (x = 0; x < (int)block_len; x++) out[x] ^= block_b[x];
    }
    else {
	for (x = 0; x < (int)block_len; x++) out[x] = block_a[x] ^ block_b[x];
    }
}

static inline int _ocb3_int_aad_add_block(cm_OCB3 *ocb, const unsigned char *aad_block)
{
    unsigned char tmp[MAXBLOCKSIZE];
    int err;

    _ocb3_int_xor_blocks(ocb->aOffset_current, ocb->aOffset_current, ocb->L_[_ocb3_int_ntz(ocb->ablock_index)], ocb->block_len);
    _ocb3_int_xor_blocks(tmp, aad_block, ocb->aOffset_current, ocb->block_len);

    if ((err = cipher_descriptor[ocb->cipher].encrypt(tmp, tmp, &ocb->cs)) != NBSCrypto_OK) {
	return err;
    }

    _ocb3_int_xor_blocks(ocb->aSum_current, ocb->aSum_current, tmp, ocb->block_len);

    ocb->ablock_index++;

    return NBSCrypto_OK;
}

static inline int _ocb3_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_OCB3 *ocb)
{
    unsigned char tmp[MAXBLOCKSIZE];
    int err, i, full_blocks;
    unsigned char *pt_b, *ct_b;

    if (len == 0) return NBSCrypto_OK;

    if ((err = is_cipher_valid(ocb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length) {
	return NBSCrypto_ERROR;
    }

    if (len % ocb->block_len) {
	return NBSCrypto_ERROR;
    }

    full_blocks = (int)len/ocb->block_len;

    for(i=0; i<full_blocks; i++) {
	pt_b = (unsigned char *)pt+i*ocb->block_len;
	ct_b = (unsigned char *)ct+i*ocb->block_len;

	_ocb3_int_xor_blocks(ocb->Offset_current, ocb->Offset_current, ocb->L_[_ocb3_int_ntz(ocb->block_index)], ocb->block_len);
	_ocb3_int_xor_blocks(tmp, pt_b, ocb->Offset_current, ocb->block_len);

	if ((err = cipher_descriptor[ocb->cipher].encrypt(tmp, tmp, &ocb->cs)) != NBSCrypto_OK) {
	    goto ERR;
	}

	_ocb3_int_xor_blocks(ct_b, tmp, ocb->Offset_current, ocb->block_len);
	_ocb3_int_xor_blocks(ocb->checksum, ocb->checksum, pt_b, ocb->block_len);

	ocb->block_index++;
    }

    err = NBSCrypto_OK;

ERR:
    return err;
}

static inline int _ocb3_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_OCB3 *ocb)
{
    unsigned char tmp[MAXBLOCKSIZE];
    int err, i, full_blocks;
    unsigned char *pt_b, *ct_b;

    if (len == 0) return NBSCrypto_OK;

    if ((err = is_cipher_valid(ocb->cipher)) != NBSCrypto_OK) {
	return err;
    }

    if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length) {
	return NBSCrypto_ERROR;
    }

    if (len % ocb->block_len) {
	return NBSCrypto_ERROR;
    }

    full_blocks = (int)len/ocb->block_len;
    for(i=0; i<full_blocks; i++) {
	pt_b = (unsigned char *)pt+i*ocb->block_len;
	ct_b = (unsigned char *)ct+i*ocb->block_len;

	_ocb3_int_xor_blocks(ocb->Offset_current, ocb->Offset_current, ocb->L_[_ocb3_int_ntz(ocb->block_index)], ocb->block_len);
	_ocb3_int_xor_blocks(tmp, ct_b, ocb->Offset_current, ocb->block_len);

	if ((err = cipher_descriptor[ocb->cipher].decrypt(tmp, tmp, &ocb->cs)) != NBSCrypto_OK) {
	    goto ERR;
	}

	_ocb3_int_xor_blocks(pt_b, tmp, ocb->Offset_current, ocb->block_len);
	_ocb3_int_xor_blocks(ocb->checksum, ocb->checksum, pt_b, ocb->block_len);

	ocb->block_index++;
    }

    err = NBSCrypto_OK;

ERR:
    return err;
}

int ocb3_add_aad(const unsigned char *aad, unsigned long aadlen, cm_OCB3 *ocb)
{
    int err, x, full_blocks, full_blocks_len, last_block_len;
    unsigned char *data;
    unsigned long datalen, l;


    if (aadlen == 0) return NBSCrypto_OK;

    if (ocb->adata_buffer_bytes > 0) {
	l = ocb->block_len - ocb->adata_buffer_bytes;
	if (l > aadlen) l = aadlen;
	memcpy(ocb->adata_buffer+ocb->adata_buffer_bytes, aad, l);
	ocb->adata_buffer_bytes += l;

	if (ocb->adata_buffer_bytes == ocb->block_len) {
	    if ((err = _ocb3_int_aad_add_block(ocb, ocb->adata_buffer)) != NBSCrypto_OK) {
		return err;
	    }
	    ocb->adata_buffer_bytes = 0;
	}

	data = (unsigned char *)aad + l;
	datalen = aadlen - l;
    }
    else {
	data = (unsigned char *)aad;
	datalen = aadlen;
    }

    if (datalen == 0) return NBSCrypto_OK;

    full_blocks = (int)(datalen/ocb->block_len);
    full_blocks_len = full_blocks * ocb->block_len;
    last_block_len = (int)(datalen - full_blocks_len);

    for (x=0; x<full_blocks; x++) {
	if ((err = _ocb3_int_aad_add_block(ocb, data+x*ocb->block_len)) != NBSCrypto_OK) {
	    return err;
	}
    }

    if (last_block_len>0) {
	memcpy(ocb->adata_buffer, data+full_blocks_len, last_block_len);
	ocb->adata_buffer_bytes = last_block_len;
    }

    return NBSCrypto_OK;
}




#pragma mark - FUNCTIONS
int ocb3_start(unsigned long cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, unsigned long taglen, cm_OCB3 *ocb)
{
    int poly, x, y, m, err;
    unsigned char *previous, *current;


    if ((err = is_cipher_valid(cipher)) != NBSCrypto_OK) {
	return err;
    }
    ocb->cipher = cipher;

    if (cipher_descriptor[cipher].block_length != 16) {
	return NBSCrypto_ERROR;
    }

    noncelen = (noncelen > cipher_descriptor[cipher].block_length) ? cipher_descriptor[cipher].block_length : noncelen;

    if (taglen > cipher_descriptor[cipher].block_length) {
	return NBSCrypto_ERROR;
    }

    ocb->tag_len = (int)taglen;
    ocb->block_len = cipher_descriptor[cipher].block_length;
    x = (int)(sizeof(polys)/sizeof(polys[0]));

    for (poly = 0; poly < x; poly++) {

	if (polys[poly].len == ocb->block_len) {
	    break;
	}
    }

    if (poly == x) {
	return NBSCrypto_ERROR;
    }

    if (polys[poly].len != ocb->block_len) {
	return NBSCrypto_ERROR;
    }

    if ((err = cipher_descriptor[cipher].setup(key, (int)keylen, 0, &ocb->cs)) != NBSCrypto_OK) {
	return err;
    }

    zeromem(ocb->L_star, ocb->block_len);

    if ((err = cipher_descriptor[cipher].encrypt(ocb->L_star, ocb->L_star, &ocb->cs)) != NBSCrypto_OK) {
	return err;
    }

    for (x = -1; x < 32; x++) {
	if (x == -1) {
	    current  = ocb->L_dollar;
	    previous = ocb->L_star;
	}
	else if (x == 0) {
	    current  = ocb->L_[0];
	    previous = ocb->L_dollar;
	}
	else {
	    current  = ocb->L_[x];
	    previous = ocb->L_[x-1];
	}
	m = previous[0] >> 7;
	for (y = 0; y < ocb->block_len-1; y++) {
	    current[y] = ((previous[y] << 1) | (previous[y+1] >> 7)) & 255;
	}
	current[ocb->block_len-1] = (previous[ocb->block_len-1] << 1) & 255;
	if (m == 1) {
	    _ocb3_int_xor_blocks(current, current, polys[poly].poly_mul, ocb->block_len);
	}
    }

    _ocb3_int_calc_offset_zero(ocb, nonce, noncelen, taglen);

    zeromem(ocb->checksum, ocb->block_len);

    ocb->block_index = 1;
    ocb->ablock_index = 1;
    ocb->adata_buffer_bytes = 0;

    zeromem(ocb->aOffset_current, ocb->block_len);
    zeromem(ocb->aSum_current, ocb->block_len);

    return NBSCrypto_OK;
}

int ocb3_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, cm_OCB3 *ocb)
{
    unsigned char iOffset_star[MAXBLOCKSIZE];
    unsigned char iPad[MAXBLOCKSIZE];
    int err, x, full_blocks, full_blocks_len, last_block_len;


    if ((err = is_cipher_valid(ocb->cipher)) != NBSCrypto_OK) {
	goto ERR;
    }

    full_blocks = (int)(len/ocb->block_len);
    full_blocks_len = full_blocks * ocb->block_len;
    last_block_len = (int)(len - full_blocks_len);

    if (full_blocks>0) {
	if ((err = _ocb3_encrypt(pt, ct, full_blocks_len, ocb)) != NBSCrypto_OK) {
	    goto ERR;
	}
    }

    if (last_block_len>0) {
	_ocb3_int_xor_blocks(iOffset_star, ocb->Offset_current, ocb->L_star, ocb->block_len);

	if ((err = cipher_descriptor[ocb->cipher].encrypt(iOffset_star, iPad, &ocb->cs)) != NBSCrypto_OK) {
	    goto ERR;
	}

	_ocb3_int_xor_blocks(ct+full_blocks_len, pt+full_blocks_len, iPad, last_block_len);
	_ocb3_int_xor_blocks(ocb->checksum, ocb->checksum, pt+full_blocks_len, last_block_len);

	for(x=last_block_len; x<ocb->block_len; x++) {
	    if (x == last_block_len) {
		ocb->checksum[x] ^= 0x80;
	    } else {
		ocb->checksum[x] ^= 0x00;
	    }
	}

	for(x=0; x<ocb->block_len; x++) {
	    ocb->tag_part[x] = (ocb->checksum[x] ^ iOffset_star[x]) ^ ocb->L_dollar[x];
	}

	if ((err = cipher_descriptor[ocb->cipher].encrypt(ocb->tag_part, ocb->tag_part, &ocb->cs)) != NBSCrypto_OK) {
	    goto ERR;
	}
    } else {
	for(x=0; x<ocb->block_len; x++) {
	    ocb->tag_part[x] = (ocb->checksum[x] ^ ocb->Offset_current[x]) ^ ocb->L_dollar[x];
	}
	if ((err = cipher_descriptor[ocb->cipher].encrypt(ocb->tag_part, ocb->tag_part, &ocb->cs)) != NBSCrypto_OK) {
	    goto ERR;
	}
    }

    err = NBSCrypto_OK;

ERR:
    return err;
}

int ocb3_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, cm_OCB3 *ocb)
{
    unsigned char iOffset_star[MAXBLOCKSIZE];
    unsigned char iPad[MAXBLOCKSIZE];
    int err, x, full_blocks, full_blocks_len, last_block_len;


    if ((err = is_cipher_valid(ocb->cipher)) != NBSCrypto_OK) {
	goto ERR;
    }

    full_blocks = (int)(len/ocb->block_len);
    full_blocks_len = full_blocks * ocb->block_len;
    last_block_len = (int)(len - full_blocks_len);

    if (full_blocks>0) {
	if ((err = _ocb3_decrypt(ct, pt, full_blocks_len, ocb)) != NBSCrypto_OK) {
	    goto ERR;
	}
    }

    if (last_block_len>0) {
	_ocb3_int_xor_blocks(iOffset_star, ocb->Offset_current, ocb->L_star, ocb->block_len);

	if ((err = cipher_descriptor[ocb->cipher].encrypt(iOffset_star, iPad, &ocb->cs)) != NBSCrypto_OK) {
	    goto ERR;
	}

	_ocb3_int_xor_blocks(pt+full_blocks_len, (unsigned char *)ct+full_blocks_len, iPad, last_block_len);
	_ocb3_int_xor_blocks(ocb->checksum, ocb->checksum, pt+full_blocks_len, last_block_len);

	for(x=last_block_len; x<ocb->block_len; x++) {
	    if (x == last_block_len) {
		ocb->checksum[x] ^= 0x80;
	    } else {
		ocb->checksum[x] ^= 0x00;
	    }
	}

	for(x=0; x<ocb->block_len; x++) {
	    ocb->tag_part[x] = (ocb->checksum[x] ^ iOffset_star[x]) ^ ocb->L_dollar[x];
	}

	if ((err = cipher_descriptor[ocb->cipher].encrypt(ocb->tag_part, ocb->tag_part, &ocb->cs)) != NBSCrypto_OK) {
	    goto ERR;
	}
    }
    else {
	for(x=0; x<ocb->block_len; x++) {
	    ocb->tag_part[x] = (ocb->checksum[x] ^ ocb->Offset_current[x]) ^ ocb->L_dollar[x];
	}

	if ((err = cipher_descriptor[ocb->cipher].encrypt(ocb->tag_part, ocb->tag_part, &ocb->cs)) != NBSCrypto_OK) {
	    goto ERR;
	}
    }

    err = NBSCrypto_OK;

ERR:
    return err;
}

int ocb3_done(unsigned char *tag, unsigned long *taglen, cm_OCB3 *ocb)
{
    unsigned char tmp[MAXBLOCKSIZE];
    int err, x;


    if ((err = is_cipher_valid(ocb->cipher)) != NBSCrypto_OK) {
	goto ERR;
    }

    if ((int)*taglen < ocb->tag_len) {
	*taglen = (unsigned long)ocb->tag_len;
	return NBSCrypto_ERROR;
    }

    if (ocb->adata_buffer_bytes>0) {
	_ocb3_int_xor_blocks(ocb->aOffset_current, ocb->aOffset_current, ocb->L_star, ocb->block_len);
	_ocb3_int_xor_blocks(tmp, ocb->adata_buffer, ocb->aOffset_current, ocb->adata_buffer_bytes);

	for(x=ocb->adata_buffer_bytes; x<ocb->block_len; x++) {
	    if (x == ocb->adata_buffer_bytes) {
		tmp[x] = 0x80 ^ ocb->aOffset_current[x];
	    }
	    else {
		tmp[x] = 0x00 ^ ocb->aOffset_current[x];
	    }
	}

	if ((err = cipher_descriptor[ocb->cipher].encrypt(tmp, tmp, &ocb->cs)) != NBSCrypto_OK) {
	    goto ERR;
	}

	_ocb3_int_xor_blocks(ocb->aSum_current, ocb->aSum_current, tmp, ocb->block_len);
    }

    _ocb3_int_xor_blocks(tmp, ocb->tag_part, ocb->aSum_current, ocb->block_len);

    for(int x = 0; x < ocb->tag_len; x++) {
	tag[x] = tmp[x];
    }
    *taglen = (unsigned long)ocb->tag_len;

    err = NBSCrypto_OK;

ERR:
    return err;
}
