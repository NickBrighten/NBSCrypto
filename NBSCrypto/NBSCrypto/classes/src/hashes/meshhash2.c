//
//	meshhash2.c
//	Authors / Developers		: Björn Fay
//	Last Modified (Original)	: 2009
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor meshhash2_128_desc =
{
    "meshhash2-128",
    178,
    16,
    64,
    &meshhash2_128_init,
    &meshhash2_process,
    &meshhash2_done,
    NULL
};

const struct hash_descriptor meshhash2_160_desc =
{
    "meshhash2-160",
    179,
    20,
    64,
    &meshhash2_160_init,
    &meshhash2_process,
    &meshhash2_done,
    NULL
};

const struct hash_descriptor meshhash2_192_desc =
{
    "meshhash2-192",
    180,
    24,
    64,
    &meshhash2_192_init,
    &meshhash2_process,
    &meshhash2_done,
    NULL
};

const struct hash_descriptor meshhash2_224_desc =
{
    "meshhash2-224",
    181,
    28,
    64,
    &meshhash2_224_init,
    &meshhash2_process,
    &meshhash2_done,
    NULL
};

const struct hash_descriptor meshhash2_256_desc =
{
    "meshhash2-256",
    182,
    32,
    64,
    &meshhash2_256_init,
    &meshhash2_process,
    &meshhash2_done,
    NULL
};

const struct hash_descriptor meshhash2_384_desc =
{
    "meshhash2-384",
    183,
    48,
    64,
    &meshhash2_384_init,
    &meshhash2_process,
    &meshhash2_done,
    NULL
};

const struct hash_descriptor meshhash2_512_desc =
{
    "meshhash2-512",
    184,
    64,
    64,
    &meshhash2_512_init,
    &meshhash2_process,
    &meshhash2_done,
    NULL
};

const struct hash_descriptor meshhash2_1024_desc =
{
    "meshhash2-1024",
    185,
    128,
    64,
    &meshhash2_1024_init,
    &meshhash2_process,
    &meshhash2_done,
    NULL
};

const struct hash_descriptor meshhash2_2048_desc =
{
    "meshhash2-2048",
    186,
    256,
    64,
    &meshhash2_2048_init,
    &meshhash2_process,
    &meshhash2_done,
    NULL
};




#pragma mark - DEFINES

#define MIN_NUMBER_OF_PIPES	4
#define MAX_NUMBER_OF_PIPES	256
#define NUMBER_OF_EXTRA_PIPES	1
#define COUNTER_LENGTH		4

#define ROT(w,b) ((b) == 0 ? (w) : ((((w) & 0xffffffffffffffffULL) >> (b) ^ (w) << (64 - (b))) & 0xffffffffffffffffULL))
#define ROT37(w) w = (((w) & 0xffffffffffffffffULL) >> 37 ^ (w) << 27) & 0xffffffffffffffffULL




#pragma mark - INLINE
static inline unsigned long long _sbox(unsigned long long w)
{
    w = w * 0x9e3779b97f4a7bb9ULL + 0x5e2d58d8b3bcdef7ULL; ROT37(w);
    w = w * 0x9e3779b97f4a7bb9ULL + 0x5e2d58d8b3bcdef7ULL; ROT37(w);
    return w;
}

static inline void _add_to_counter(unsigned long long counter[], unsigned long long to_add)
{
    unsigned long long temp;
    int i, carry;

    carry = 0;
    for (i = 0; i < COUNTER_LENGTH; i++){
	temp = (to_add & 0xffffffffffffffffULL) + carry & 0xffffffffffffffffULL;
	counter[i] += temp;
	counter[i] &= 0xffffffffffffffffULL;

	if (carry == 1 && temp == 0)
	    carry = 1;
	else if (counter[i] < temp)
	    carry = 1;
	else
	    carry = 0;

	to_add >>= 32;
	to_add >>= 32;
    }

    return;
}

static inline void _normal_round(hash_state *hs, unsigned long long data)
{
    int i;
    unsigned long long *pipe;

    pipe = hs->meshhash2.pipe;
    pipe[hs->meshhash2.number_of_pipes] = pipe[0];

    for (i = 0; i < hs->meshhash2.number_of_pipes; i++){
	pipe[i] = pipe[i] ^ i*0x0101010101010101ULL ^ data;
	pipe[i]	= ROT(pipe[i], i*37 & 63);
	pipe[i]	= _sbox(pipe[i]);
	pipe[i] = pipe[i] + pipe[i+1] & 0xffffffffffffffffULL;
    }

    hs->meshhash2.feedback[hs->meshhash2.block_counter[0] & 1ULL][hs->meshhash2.block_round_counter] = pipe[hs->meshhash2.block_round_counter];

    hs->meshhash2.block_round_counter++;
    return;
}

static inline void _final_block_round(hash_state *hs)
{
    int i,j;

    int number_of_pipes;
    unsigned long long *pipe;

    pipe = hs->meshhash2.pipe;
    number_of_pipes = hs->meshhash2.number_of_pipes;

    hs->meshhash2.block_round_counter = 0;

    for (i = 0; i < number_of_pipes; i++)
	pipe[i] = _sbox(pipe[i] ^ hs->meshhash2.block_counter[i % COUNTER_LENGTH]);

    _add_to_counter(hs->meshhash2.block_counter, 1);

    if (hs->meshhash2.key_length > 0){
	for (i = hs->meshhash2.key_counter; i < hs->meshhash2.key_length + hs->meshhash2.key_counter; i += number_of_pipes)
	    for (j = 0; j < number_of_pipes; j++)
		pipe[j] = _sbox(pipe[j] ^ hs->meshhash2.key[(i + j) % hs->meshhash2.key_length]);

	hs->meshhash2.key_counter = (hs->meshhash2.key_counter + 1) % hs->meshhash2.key_length;

	for (i = 0; i < number_of_pipes; i++)
	    hs->meshhash2.pipe[i] = _sbox(hs->meshhash2.pipe[i] ^ (unsigned long long)hs->meshhash2.key_length ^ i*0x0101010101010101ULL);
    }

    for (i = 0; i < number_of_pipes; i++){
	pipe[i] = _sbox(pipe[i] ^ hs->meshhash2.feedback[ hs->meshhash2.block_counter[0] & 1ULL   ][i]);
	pipe[i] = _sbox(pipe[i] ^ hs->meshhash2.feedback[(hs->meshhash2.block_counter[0] & 1ULL)^1][i]);
    }

    return;
}

static inline void _final_rounds(hash_state *state)
{
    int i,j;

    if (state->meshhash2.data_counter > 0){
	state->meshhash2.data_buffer <<= 8 * (8 - state->meshhash2.data_counter);
	_normal_round(state, state->meshhash2.data_buffer);
	state->meshhash2.data_counter = 0;
	state->meshhash2.data_buffer = 0;
    }

    if (state->meshhash2.block_round_counter != 0){
	while (state->meshhash2.block_round_counter < state->meshhash2.number_of_pipes)
	    _normal_round(state, 0);

	_final_block_round(state);
    }

    for (i = 0; i < state->meshhash2.number_of_pipes; i++)
	_normal_round(state, 0);

    _final_block_round(state);

    for (i = 0; i < COUNTER_LENGTH; i++)
	for (j = 0; j < state->meshhash2.number_of_pipes; j++)
	    state->meshhash2.pipe[j] = _sbox(state->meshhash2.pipe[j] ^ state->meshhash2.bit_counter[i] ^ j*0x0101010101010101ULL);

    for (i = 0; i < state->meshhash2.number_of_pipes; i++)
	state->meshhash2.pipe[i] = _sbox(state->meshhash2.pipe[i] ^ (unsigned long long)state->meshhash2.hashbitlen ^ i*0x0101010101010101ULL);

    state->meshhash2.squeezing = 1;
}

static inline int _computeNumberOfPipes(int hashbitlen)
{
    int number_of_pipes;

    number_of_pipes = (hashbitlen + 63) / 64;
    number_of_pipes += (NUMBER_OF_EXTRA_PIPES);
    if (number_of_pipes < MIN_NUMBER_OF_PIPES)
	number_of_pipes = MIN_NUMBER_OF_PIPES;
    if (number_of_pipes > MAX_NUMBER_OF_PIPES)
	number_of_pipes = MAX_NUMBER_OF_PIPES;
    return number_of_pipes;
}

static inline int _squeezeNBytes(hash_state *state, unsigned char *hashval, int rounds)
{
    int i,j;
    unsigned long long temp;

    if (!state->meshhash2.squeezing)
	_final_rounds(state);

    for (i = 0; i < rounds; i++){
	_normal_round(state, 0);

	temp = 0;
	for (j = 0; j < state->meshhash2.number_of_pipes; j += 2)
	    temp ^= state->meshhash2.pipe[j];

	hashval[i] = temp & 0xff;

	if (state->meshhash2.block_round_counter == state->meshhash2.number_of_pipes)
	    _final_block_round(state);
    }

    return NBSCrypto_OK;
}

static inline int _init3(hash_state *state, int hashbitlen, int number_of_pipes, int keybytelen, unsigned char *key)
{
    int i, error;

    if (hashbitlen % 8 != 0 || hashbitlen < 0 || hashbitlen > 0x7fff)
	return NBSCrypto_ERROR;

    state->meshhash2.hashbitlen = hashbitlen;
    state->meshhash2.number_of_pipes = number_of_pipes;

    if (keybytelen % 8 != 0 || keybytelen < 0 || keybytelen > 0x7fff)
	return NBSCrypto_ERROR;

    state->meshhash2.key_length = keybytelen/8;

    if (state->meshhash2.key_length > 0){
	state->meshhash2.key = calloc(state->meshhash2.key_length, sizeof(unsigned long long));
	if (state->meshhash2.key == NULL)
	    return NBSCrypto_ERROR;
	for (i = 0; i < state->meshhash2.key_length; i++)
	    state->meshhash2.key[i] =	(unsigned long long)(key[8*i] & 0xff) << 56
	    ^ (unsigned long long)(key[8*i+1] & 0xff) << 48
	    ^ (unsigned long long)(key[8*i+2] & 0xff) << 40
	    ^ (unsigned long long)(key[8*i+3] & 0xff) << 32
	    ^ (unsigned long long)(key[8*i+4] & 0xff) << 24
	    ^ (unsigned long long)(key[8*i+5] & 0xff) << 16
	    ^ (unsigned long long)(key[8*i+6] & 0xff) << 8
	    ^ (unsigned long long)(key[8*i+7] & 0xff);
    }else
	state->meshhash2.key = NULL;

    state->meshhash2.block_round_counter = 0;
    state->meshhash2.key_counter = 0;
    state->meshhash2.data_counter = 0;
    state->meshhash2.data_buffer = 0;
    state->meshhash2.squeezing = 0;

    state->meshhash2.pipe = calloc(number_of_pipes + 1, sizeof(unsigned long long));
    if (state->meshhash2.pipe == NULL)
	return NBSCrypto_ERROR;

    state->meshhash2.feedback[0] = calloc(number_of_pipes, sizeof(unsigned long long));
    if (state->meshhash2.feedback[0] == NULL)
	return NBSCrypto_ERROR;

    state->meshhash2.feedback[1] = calloc(number_of_pipes, sizeof(unsigned long long));
    if (state->meshhash2.feedback[1] == NULL)
	return NBSCrypto_ERROR;

    for (i = 0; i < COUNTER_LENGTH; i++){
	state->meshhash2.bit_counter[i] = 0;
	state->meshhash2.block_counter[i] = 0;
    }

    error = NBSCrypto_OK;
    if (state->meshhash2.key_length > 0)
	error = meshhash2_process(state, key, 8*keybytelen);

    for (i = 0; i < COUNTER_LENGTH; i++){
	state->meshhash2.bit_counter[i] = 0;
    }

    return error;
}

static inline int _meshhash2_init(hash_state *state, int hashbitlen)
{
    return _init3(state, hashbitlen, _computeNumberOfPipes(hashbitlen), 0, NULL);
}

static inline void _deinit(hash_state *hs)
{
    free(hs->meshhash2.pipe);
    free(hs->meshhash2.feedback[0]);
    free(hs->meshhash2.feedback[1]);
    if (hs->meshhash2.key_length>0)
	free(hs->meshhash2.key);
}




#pragma mark - FUNCTIONS

int meshhash2_128_init(hash_state *hs){return _meshhash2_init(hs, 128);}
int meshhash2_160_init(hash_state *hs){return _meshhash2_init(hs, 160);}
int meshhash2_192_init(hash_state *hs){return _meshhash2_init(hs, 192);}
int meshhash2_224_init(hash_state *hs){return _meshhash2_init(hs, 224);}
int meshhash2_256_init(hash_state *hs){return _meshhash2_init(hs, 256);}
int meshhash2_384_init(hash_state *hs){return _meshhash2_init(hs, 384);}
int meshhash2_512_init(hash_state *hs){return _meshhash2_init(hs, 512);}
int meshhash2_1024_init(hash_state *hs){return _meshhash2_init(hs, 1024);}
int meshhash2_2048_init(hash_state *hs){return _meshhash2_init(hs, 2048);}

int meshhash2_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    const unsigned char *end;

    _add_to_counter(hs->meshhash2.bit_counter, inlen);

    while (inlen > 0){
	if (hs->meshhash2.data_counter == 0){
	    end = in + (inlen / 8 & ~(unsigned long long)7);
	    inlen -= inlen & ~(unsigned long long)63;
	    while(in != end){
		_normal_round(hs,  (unsigned long long)*in << 56
			      ^ (unsigned long long)*(in+1) << 48
			      ^ (unsigned long long)*(in+2) << 40
			      ^ (unsigned long long)*(in+3) << 32
			      ^ (unsigned long long)*(in+4) << 24
			      ^ (unsigned long long)*(in+5) << 16
			      ^ (unsigned long long)*(in+6) <<  8
			      ^ (unsigned long long)*(in+7));
		if (hs->meshhash2.block_round_counter == hs->meshhash2.number_of_pipes)
		    _final_block_round(hs);
		in += 8;
	    }
	}

	if (inlen >= 8){
	    hs->meshhash2.data_buffer <<= 8;
	    hs->meshhash2.data_buffer |= *in;
	    in++;
	    inlen -= 8;
	    hs->meshhash2.data_counter++;
	}else if (inlen > 0){
	    hs->meshhash2.data_buffer <<= 8;
	    hs->meshhash2.data_buffer |= *in >> (8-inlen) << (8-inlen) & 0xff;
	    inlen = 0;
	    hs->meshhash2.data_counter++;
	}

	if (hs->meshhash2.data_counter == 8){
	    _normal_round(hs, hs->meshhash2.data_buffer);
	    if (hs->meshhash2.block_round_counter == hs->meshhash2.number_of_pipes)
		_final_block_round(hs);
	    hs->meshhash2.data_counter = 0;
	    hs->meshhash2.data_buffer = 0;
	}
    }

    return NBSCrypto_OK;
}

int meshhash2_done(hash_state *hs, unsigned char *out)
{
    int error;

    error = _squeezeNBytes(hs, out, hs->meshhash2.hashbitlen / 8);
    _deinit(hs);
    return error;
}
